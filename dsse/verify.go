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

package dsse

import (
	"bytes"
	"context"
	"crypto/x509"
	"time"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/timestamp"
)

type verificationOptions struct {
	roots                []*x509.Certificate
	intermediates        []*x509.Certificate
	verifiers            []cryptoutil.Verifier
	threshold            int
	timestampAuthorities []timestamp.Timestamper
}

type VerificationOption func(*verificationOptions)

func VerifyWithRoots(roots ...*x509.Certificate) VerificationOption {
	return func(vo *verificationOptions) {
		vo.roots = roots
	}
}

func VerifyWithIntermediates(intermediates ...*x509.Certificate) VerificationOption {
	return func(vo *verificationOptions) {
		vo.intermediates = intermediates
	}
}

func VerifyWithVerifiers(verifiers ...cryptoutil.Verifier) VerificationOption {
	return func(vo *verificationOptions) {
		vo.verifiers = verifiers
	}
}

func VerifyWithThreshold(threshold int) VerificationOption {
	return func(vo *verificationOptions) {
		vo.threshold = threshold
	}
}

func VerifyWithTimestampAuthorities(timestampers ...timestamp.Timestamper) VerificationOption {
	return func(vo *verificationOptions) {
		vo.timestampAuthorities = timestampers
	}
}

type PassedVerifier struct {
	Verifier           cryptoutil.Verifier
	TimestampAuthority TimestampInfo
}

type TimestampInfo struct {
	Timestamp time.Time
	URL       string
}

func VerifyOpts(verifiers []cryptoutil.Verifier, roots []*x509.Certificate, intermediates []*x509.Certificate, timestampers []timestamp.Timestamper) []VerificationOption {
	return []VerificationOption{
		VerifyWithVerifiers(verifiers...),
		VerifyWithRoots(roots...),
		VerifyWithIntermediates(intermediates...),
		VerifyWithTimestampAuthorities(timestampers...),
	}
}

func (e Envelope) Verify(opts ...VerificationOption) ([]PassedVerifier, error) {
	options := &verificationOptions{
		threshold: 1,
	}

	for _, opt := range opts {
		opt(options)
	}

	if options.threshold <= 0 {
		return nil, ErrInvalidThreshold(options.threshold)
	}

	if len(e.Signatures) == 0 {
		return nil, ErrNoSignatures{}
	}

	pae := preauthEncode(e.PayloadType, e.Payload)

	passedVerifiers := make([]PassedVerifier, 0)
	for _, sig := range e.Signatures {
		if sig.Certificate != nil && len(sig.Certificate) > 0 {
			if pvs, err := verifyX509Time(sig, pae, options); err == nil {
				passedVerifiers = append(passedVerifiers, pvs...)
			}
		}

		for _, verifier := range options.verifiers {
			if verifier != nil {
				if err := verifier.Verify(bytes.NewReader(pae), sig.Signature); err == nil {
					passedVerifiers = append(passedVerifiers, PassedVerifier{Verifier: verifier})
				}
			}
		}
	}

	// NOTE: Should we still pursue this logic if we verified with certificates...?
	if len(passedVerifiers) == 0 {
		return nil, ErrNoMatchingSigs{}
	} else if len(passedVerifiers) < options.threshold {
		return passedVerifiers, ErrThresholdNotMet{Theshold: options.threshold, Acutal: len(passedVerifiers)}
	}

	return passedVerifiers, nil
}

func verifyX509Time(sig Signature, pae []byte, opts *verificationOptions) ([]PassedVerifier, error) {
	cert, err := cryptoutil.TryParseCertificate(sig.Certificate)
	if err != nil {
		return nil, err
	}

	ints := make([]*x509.Certificate, 0)
	if len(opts.intermediates) > 0 {
		ints = append(ints, opts.intermediates...)
	}

	for _, int := range sig.Intermediates {
		intCert, err := cryptoutil.TryParseCertificate(int)
		if err != nil {
			continue
		}

		ints = append(ints, intCert)
	}

	var trustedTimes []TimestampInfo
	if len(opts.timestampAuthorities) == 0 {
		trustedTimes = append(trustedTimes, TimestampInfo{Timestamp: time.Now()})
	} else {
		for _, timestampVerifier := range opts.timestampAuthorities {
			for _, sigTimestamp := range sig.Timestamps {
				tt, err := timestampVerifier.Verify(context.TODO(), bytes.NewReader(sigTimestamp.Data), bytes.NewReader(sig.Signature))
				if err != nil {
					continue
				}
				trustedTimes = append(trustedTimes, TimestampInfo{URL: timestampVerifier.Url(context.TODO()), Timestamp: tt})
			}
		}
	}

	var pvs []PassedVerifier
	for _, tt := range trustedTimes {
		v, err := cryptoutil.NewX509Verifier(cert, ints, opts.roots, tt.Timestamp)
		if err != nil {
			return nil, err
		}

		if err := v.Verify(bytes.NewReader(pae), sig.Signature); err != nil {
			return nil, err
		}

		if tt.URL != "" {
			tt = TimestampInfo{}
		}

		pvs = append(pvs,
			PassedVerifier{
				Verifier:           v,
				TimestampAuthority: tt,
			},
		)
	}

	return pvs, nil
}
