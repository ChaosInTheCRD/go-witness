// Copyright 2024 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sbom

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
	spdx "github.com/spdx/tools-golang/spdx"
)

const (
	Name    = "sbom"
	Type    = "https://witness.dev/attestations/sbom/v0.1"
	RunType = attestation.PostProductRunType

	SPDXPredicateType      = "https://spdx.dev/Document"
	SPDXMimeType           = "application/spdx+json"
	CycloneDxPredicateType = "https://cyclonedx.org/bom"
	CycloneDxMimeType      = "application/vnd.cyclonedx+json"
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor = &SBOMAttestor{}
	_ attestation.Exporter = &SBOMAttestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return NewSBOMAttestor()
	},

		registry.BoolConfigOption(
			"export",
			"Export the Link predicate in its own attestation",
			false,
			func(a attestation.Attestor, export bool) (attestation.Attestor, error) {
				sbomAttestor, ok := a.(*SBOMAttestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a Link provenance attestor", a)
				}
				WithExport(export)(sbomAttestor)
				return sbomAttestor, nil
			},
		),
	)
}

type Option func(*SBOMAttestor)

func WithExport(export bool) Option {
	return func(a *SBOMAttestor) {
		a.export = export
	}
}

type SBOMAttestor struct {
	SBOMDocument  interface{}
	predicateType string
	export        bool
	subjects      map[string]string
}

func NewSBOMAttestor() *SBOMAttestor {
	return &SBOMAttestor{
		predicateType: Type,
	}
}

func (a *SBOMAttestor) Name() string {
	return Name
}

func (a *SBOMAttestor) Type() string {
	return a.predicateType
}

func (a *SBOMAttestor) RunType() attestation.RunType {
	return RunType
}

func (a *SBOMAttestor) Export() bool {
	return a.export
}

func (a *SBOMAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

func (a *SBOMAttestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	for k, v := range a.subjects {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(v), hashes); err == nil {
			subjects[fmt.Sprintf("%s:%s", k, v)] = ds
		} else {
			log.Debugf("(attestation/sbom) failed to record %v subject: %w", k, err)
		}
	}

	return subjects
}

func (a *SBOMAttestor) Attest(ctx *attestation.AttestationContext) error {
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/sbom) error getting candidate: %w", err)
		return err
	}

	return nil
}

func (a *SBOMAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(&a.SBOMDocument)
}

func (a *SBOMAttestor) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &a.SBOMDocument); err != nil {
		return err
	}

	return nil
}

func (a *SBOMAttestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()

	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		if product.MimeType == SPDXMimeType {
			a.predicateType = SPDXPredicateType
		} else if product.MimeType == CycloneDxMimeType {
			a.predicateType = CycloneDxPredicateType
		} else {
			continue
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("error opening file: %s", path)
		}

		sbomBytes, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("error reading file: %s", path)
		}

		a.subjects = make(map[string]string)
		switch a.predicateType {
		case SPDXPredicateType:
			var document *spdx.Document
			err := json.Unmarshal(sbomBytes, &document)
			if err != nil {
				return fmt.Errorf("error unmarshaling SPDX document: %w", err)
			}

			// NOTE: Getting the version from the SPDX document seemed pretty unclear, leaving it for now
			if document.DocumentName != "" {
				a.subjects["name"] = document.DocumentName
			}
		case CycloneDxPredicateType:
			bom := cyclonedx.NewBOM()
			decoder := cyclonedx.NewBOMDecoder(bytes.NewReader(sbomBytes), cyclonedx.BOMFileFormatJSON)
			err := decoder.Decode(bom)
			if err != nil {
				return fmt.Errorf("error decoding CycloneDX BOM: %w", err)
			}

			if bom.Metadata.Component.Name != "" {
				a.subjects["name"] = bom.Metadata.Component.Name
			}

			if bom.Metadata.Component.Version != "" {
				a.subjects["version"] = bom.Metadata.Component.Name
			}

		default:
			return fmt.Errorf("unsupported predicate type: %s", a.predicateType)
		}

		var sbomDocument interface{}
		if err := json.Unmarshal(sbomBytes, &sbomDocument); err != nil {
			log.Debugf("(attestation/sbom) error unmarshaling SBOM: %w", err)
			continue
		}

		a.SBOMDocument = sbomDocument

		return nil
	}

	return fmt.Errorf("no SBOM file found")
}
