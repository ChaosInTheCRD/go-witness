package custom

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/in-toto/go-witness/attestation"
	"github.com/qri-io/jsonschema"
)

type CustomAttestor struct {
	ValidatedType string
	Definition    attestation.CustomAttestorDefinition
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

type OutputAttestation struct {
	Type        string                 `json:"type"`
	Attestation map[string]interface{} `json:"attestation"`
}

func (c *CustomAttestor) Name() string {
	return c.Definition.Metadata.Name
}

func (c *CustomAttestor) RunType() attestation.RunType {
	return attestation.ParseRunType(c.Definition.Spec.RunType)
}

func (c *CustomAttestor) Type() string {
	// This isn't optimal. However at the start of the run we aren't necessarily sure of the version that is in use. Maybe this isn't preferable.
	if c.ValidatedType == "" {
		return c.Definition.Metadata.Type
	}

	return c.ValidatedType
}

func (c *CustomAttestor) Attest(ctx *attestation.AttestationContext) error {
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
			return fmt.Errorf("error running custom attestor: %v", err)
		}
	} else {
		return fmt.Errorf("executor type not supported")
	}

	// verify the output against the json Schema
	var schema *jsonschema.Schema
	var att OutputAttestation
	err = json.Unmarshal(output, &att)
	if err != nil {
		return fmt.Errorf("error unmarshalling custom attestor output: %v", err)
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
		return fmt.Errorf("error marshalling custom attestor output: %v", err)
	}

	errs, err := schema.ValidateBytes(context.Background(), out)
	if err != nil {
		return fmt.Errorf("error validating custom attestor output: %v", err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("outputted JSON does not match schema: %v", errs)
	}

	c.Output = output

	return nil
}
