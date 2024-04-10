// Copyright 2022 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package witness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/environment"
	"github.com/in-toto/go-witness/attestation/git"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/timestamp"
)

type runOptions struct {
	stepName        string
	signer          cryptoutil.Signer
	attestors       []attestation.Attestor
	attestationOpts []attestation.AttestationContextOption
	timestampers    []timestamp.Timestamper
}

type RunOption func(ro *runOptions)

func RunWithAttestors(attestors []attestation.Attestor) RunOption {
	return func(ro *runOptions) {
		ro.attestors = attestors
	}
}

func RunWithAttestationOpts(opts ...attestation.AttestationContextOption) RunOption {
	return func(ro *runOptions) {
		ro.attestationOpts = opts
	}
}

func RunWithTimestampers(ts ...timestamp.Timestamper) RunOption {
	return func(ro *runOptions) {
		ro.timestampers = ts
	}
}

type RunResult struct {
	Collection     attestation.Collection
	SignedEnvelope dsse.Envelope
}

type attestorError struct {
	Attestor string
	Error    error
}

func Run(stepName string, signer cryptoutil.Signer, opts ...RunOption) (RunResult, error) {
	log.Info("Running witness")
	ro := runOptions{
		stepName:  stepName,
		signer:    signer,
		attestors: []attestation.Attestor{environment.New(), git.New()},
	}

	for _, opt := range opts {
		opt(&ro)
	}

	result := RunResult{}

	log.Info("creating attestation context")
	runCtx, err := attestation.NewContext(ro.attestors, ro.attestationOpts...)
	if err != nil {
		return result, fmt.Errorf("failed to create attestation context: %w", err)
	}

	log.Info("Running attestors")
	if err = runCtx.RunAttestors(); err != nil {
		return result, fmt.Errorf("failed to run attestors: %w", err)
	}

	aerrs := make([]attestorError, 0)
	for _, r := range runCtx.CompletedAttestors() {
		if r.Error != nil {
			log.Info("Attestor failed: ", r.Attestor.Name(), " Error: ", r.Error)
			aerrs = append(aerrs, attestorError{Attestor: r.Attestor.Name(), Error: r.Error})
		}
	}

	if len(aerrs) > 0 {
		errs := []error{errors.New("attestors failed with error messages")}
		for _, e := range aerrs {
			errs = append(errs, fmt.Errorf("attestor: %s, error: %s", e.Attestor, e.Error))
		}
		return result, errors.Join(errs...)
	}

	result.Collection = attestation.NewCollection(ro.stepName, runCtx.CompletedAttestors())
	if ro.signer == nil {
		log.Warn("No signer provided, skipping signing")
	} else {
		result.SignedEnvelope, err = SignCollection(result.Collection, dsse.SignWithSigners(ro.signer), dsse.SignWithTimestampers(ro.timestampers...))
		if err != nil {
			return result, fmt.Errorf("failed to sign collection: %w", err)
		}
	}

	return result, nil
}

func validateRunOpts(ro runOptions) error {
	if ro.stepName == "" {
		return fmt.Errorf("step name is required")
	}

	if ro.signer == nil {
		return fmt.Errorf("signer is required")
	}

	return nil
}

func SignCollection(collection attestation.Collection, opts ...dsse.SignOption) (dsse.Envelope, error) {
	data, err := json.Marshal(&collection)
	if err != nil {
		return dsse.Envelope{}, err
	}

	stmt, err := intoto.NewStatement(attestation.CollectionType, data, collection.Subjects())
	if err != nil {
		return dsse.Envelope{}, err
	}

	stmtJson, err := json.Marshal(&stmt)
	if err != nil {
		return dsse.Envelope{}, err
	}

	return dsse.Sign(intoto.PayloadType, bytes.NewReader(stmtJson), opts...)
}
