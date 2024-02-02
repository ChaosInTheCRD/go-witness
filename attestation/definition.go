package attestation

import "github.com/qri-io/jsonschema"

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
