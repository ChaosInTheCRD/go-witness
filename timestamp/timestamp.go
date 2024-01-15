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

package timestamp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"github.com/in-toto/go-witness/cryptoutil"
)

// Timestamper provides the way to
type Timestamper interface {
	Timestamp(context.Context, io.Reader) ([]byte, error)
	Verify(context.Context, io.Reader, io.Reader) (time.Time, error)
	Url(context.Context) string
}

type TimestampAuthority struct {
	url                string
	hash               crypto.Hash
	requestCertificate bool
	certChain          *x509.CertPool
}

type TimestampAuthorityOption func(*TimestampAuthority)

func TimestampWithURL(url string) TimestampAuthorityOption {
	return func(t *TimestampAuthority) {
		t.url = url
	}
}

func TimestampWithHash(h crypto.Hash) TimestampAuthorityOption {
	return func(t *TimestampAuthority) {
		t.hash = h
	}
}

func TimestampWithRequestCertificate(requestCertificate bool) TimestampAuthorityOption {
	return func(t *TimestampAuthority) {
		t.requestCertificate = requestCertificate
	}
}

func VerifyWithCertChain(certs []*x509.Certificate) TimestampAuthorityOption {
	return func(t *TimestampAuthority) {
		t.certChain = x509.NewCertPool()
		for _, cert := range certs {
			t.certChain.AddCert(cert)
		}
	}
}

func NewTimestampAuthority(opts ...TimestampAuthorityOption) TimestampAuthority {
	t := TimestampAuthority{
		hash:               crypto.SHA256,
		requestCertificate: true,
	}

	for _, opt := range opts {
		opt(&t)
	}

	return t
}

func (t TimestampAuthority) Timestamp(ctx context.Context, r io.Reader) ([]byte, error) {
	tsq, err := timestamp.CreateRequest(r, &timestamp.RequestOptions{
		Hash:         t.hash,
		Certificates: t.requestCertificate,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", t.url, bytes.NewReader(tsq))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/timestamp-query")
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
	default:
		return nil, fmt.Errorf("request to timestamp authority failed: %v", resp.Status)
	}

	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	timestamp, err := timestamp.ParseResponse(bodyBytes)
	if err != nil {
		return nil, err
	}

	return timestamp.RawToken, nil
}

func (t TimestampAuthority) Verify(ctx context.Context, tsrData, signedData io.Reader) (time.Time, error) {
	tsrBytes, err := io.ReadAll(tsrData)
	if err != nil {
		return time.Time{}, err
	}

	ts, err := timestamp.Parse(tsrBytes)
	if err != nil {
		return time.Time{}, err
	}

	hashedData, err := cryptoutil.Digest(signedData, t.hash)
	if err != nil {
		return time.Time{}, err
	}

	if !bytes.Equal(ts.HashedMessage, hashedData) {
		return time.Time{}, fmt.Errorf("signed payload does not match timestamped payload")
	}

	p7, err := pkcs7.Parse(tsrBytes)
	if err != nil {
		return time.Time{}, err
	}

	if err := p7.VerifyWithChain(t.certChain); err != nil {
		return time.Time{}, err
	}

	return ts.Time, nil
}

func (t TimestampAuthority) Url(ctx context.Context) string {
	return t.url
}
