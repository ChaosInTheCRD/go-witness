// Copyright 2021 The Witness Contributors
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

package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/registry"
	"github.com/qri-io/jsonschema"
)

var (
	attestorRegistry   = registry.New[Attestor]()
	attestationsByType = map[string]registry.Entry[Attestor]{}
	attestationsByRun  = map[RunType]registry.Entry[Attestor]{}
)

type Attestor interface {
	Name() string
	Type() string
	RunType() RunType
	Attest(ctx *AttestationContext) error
}

type CustomAttestor struct {
	ValidatedType string
	Definition    CustomAttestorDefinition
	Output        []byte
}

func (c *CustomAttestor) MarshalJSON() ([]byte, error) {
	var out OutputAttestation
	err := json.Unmarshal(c.Output, &out)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out.Attestation)
}

type CustomAttestorDefinition struct {
	Version  string   `json:"version" yaml:"version"`
	Metadata Metadata `json:"metadata" yaml:"metadata"`
	Spec     Spec     `json:"spec" yaml:"spec"`
}

type Metadata struct {
	Name string `json:"name" yaml:"name"`
	Type string `json:"type" yaml:"type"`
}

type Spec struct {
	RunType  string    `json:"runType" yaml:"runType"`
	Executor Executor  `json:"executor" yaml:"executor"`
	Versions []Version `json:"versions" yaml:"versions"`
}

type Executor struct {
	Attest Execute `json:"attest" yaml:"attest"`
	Verify Execute `json:"verify" yaml:"verify"`
}

type Execute struct {
	Type      string   `json:"type" yaml:"type"`
	Arguments []string `json:"arguments" yaml:"arguments"`
}

type Version struct {
	Name   string            `json:"name" yaml:"name"`
	Schema jsonschema.Schema `json:"schema" yaml:"schema"`
}

type OutputAttestation struct {
	Type        string                 `json:"type"`
	Attestation map[string]interface{} `json:"attestation"`
}

func (c *CustomAttestor) Name() string {
	return c.Definition.Metadata.Name
}

func (c *CustomAttestor) RunType() RunType {
	return ParseRunType(c.Definition.Spec.RunType)
}

func (c *CustomAttestor) Type() string {
	return c.ValidatedType
}

func (c *CustomAttestor) Attest(ctx *AttestationContext) error {
	attest := c.Definition.Spec.Executor.Attest
	var output []byte
	var err error
	if attest.Type == "command" {
		var command string
		var args []string
		if len(attest.Arguments) == 0 {
			return fmt.Errorf("no command specified")
		} else if len(attest.Arguments) == 1 {
			command = attest.Arguments[0]
		} else {
			command = attest.Arguments[0]
			args = attest.Arguments[1:]
		}

		cmd := exec.Command(command, args...)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Error running custom attestor: %v", err)
		}
	} else {
		return fmt.Errorf("Executor type not supported")
	}

	// verify the output against the json Schema
	var schema *jsonschema.Schema
	var att OutputAttestation
	err = json.Unmarshal(output, &att)
	if err != nil {
		return fmt.Errorf("Error unmarshalling custom attestor output: %v", err)
	}
	for _, v := range c.Definition.Spec.Versions {
		t := fmt.Sprintf("%s/%s/%s", c.Definition.Metadata.Type, c.Definition.Metadata.Name, v.Name)
		if att.Type == t {
			c.ValidatedType = t
			schema = &v.Schema
			break
		}
	}

	if c.ValidatedType == "" {
		return fmt.Errorf("no matching version found for attestation outputted by custom attestor")
	}

	out, err := json.Marshal(att.Attestation)
	if err != nil {
		return fmt.Errorf("Error marshalling custom attestor output: %v", err)
	}

	errs, err := schema.ValidateBytes(context.Background(), out)
	if err != nil {
		return fmt.Errorf("Error validating custom attestor output: %v", err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("outputted JSON does not match schema: %v", errs)
	}

	c.Output = output

	return nil
}

// Subjecter allows attestors to expose bits of information that will be added to
// the in-toto statement as subjects. External services such as Rekor and Archivista
// use in-toto subjects as indexes back to attestations.
type Subjecter interface {
	Subjects() map[string]cryptoutil.DigestSet
}

// Materialer allows attestors to communicate about materials that were observed
// while the attestor executed. For example the material attestor records the hashes
// of all files before a command is run.
type Materialer interface {
	Materials() map[string]cryptoutil.DigestSet
}

// Producer allows attestors to communicate that some product was created while the
// attestor executed. For example the product attestor runs after a command run and
// finds files that did not exist in the working directory prior to the command's
// execution.
type Producer interface {
	Products() map[string]Product
}

// BackReffer allows attestors to indicate which of their subjects are good candidates
// to find related attestations.  For example the git attestor's commit hash subject
// is a good candidate to find all attestation collections that also refer to a specific
// git commit.
type BackReffer interface {
	BackRefs() map[string]cryptoutil.DigestSet
}

type ErrAttestationNotFound string

func (e ErrAttestationNotFound) Error() string {
	return fmt.Sprintf("attestation not found: %v", string(e))
}

type ErrAttestorNotFound string

func (e ErrAttestorNotFound) Error() string {
	return fmt.Sprintf("attestor not found: %v", string(e))
}

func RegisterAttestation(name, predicateType string, run RunType, factoryFunc registry.FactoryFunc[Attestor], opts ...registry.Configurer) {
	registrationEntry := attestorRegistry.Register(name, factoryFunc, opts...)
	attestationsByType[predicateType] = registrationEntry
	attestationsByRun[run] = registrationEntry
}

func RegisterCustomAttestation(definition CustomAttestorDefinition) {
	registrationEntry := attestorRegistry.Register(definition.Metadata.Name, func() Attestor {
		return &CustomAttestor{Definition: definition}
	})
	attestationsByType[definition.Metadata.Type] = registrationEntry
	attestationsByRun[ParseRunType(definition.Spec.RunType)] = registrationEntry
}

func FactoryByType(uri string) (registry.FactoryFunc[Attestor], bool) {
	registrationEntry, ok := attestationsByType[uri]
	return registrationEntry.Factory, ok
}

func FactoryByName(name string) (registry.FactoryFunc[Attestor], bool) {
	registrationEntry, ok := attestorRegistry.Entry(name)
	return registrationEntry.Factory, ok
}

func GetAttestor(nameOrType string) (Attestor, error) {
	attestors, err := GetAttestors([]string{nameOrType})
	if err != nil {
		return nil, err
	}

	if len(attestors) == 0 {
		return nil, ErrAttestorNotFound(nameOrType)
	}

	return attestors[0], nil
}

// Deprecated: use AddAttestors instead
func Attestors(nameOrTypes []string) ([]Attestor, error) {
	return GetAttestors(nameOrTypes)
}

func GetAttestors(nameOrTypes []string) ([]Attestor, error) {
	attestors := make([]Attestor, 0)
	for _, nameOrType := range nameOrTypes {
		factory, ok := FactoryByName(nameOrType)
		if !ok {
			factory, ok = FactoryByType(nameOrType)
			if !ok {
				return nil, ErrAttestorNotFound(nameOrType)
			}
		}

		attestor := factory()
		opts := AttestorOptions(nameOrType)
		attestor, err := attestorRegistry.SetDefaultVals(attestor, opts)
		if err != nil {
			return nil, err
		}

		attestors = append(attestors, attestor)
	}

	return attestors, nil
}

func AttestorOptions(nameOrType string) []registry.Configurer {
	entry, ok := attestorRegistry.Entry(nameOrType)
	if !ok {
		entry = attestationsByType[nameOrType]
	}

	return entry.Options
}

func RegistrationEntries() []registry.Entry[Attestor] {
	return attestorRegistry.AllEntries()
}
