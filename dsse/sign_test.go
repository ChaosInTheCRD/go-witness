package dsse

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wrapping the timestamper so we can check whether it's expected or not
type testTimestamper struct {
	expect bool
	ts     timestamp.Timestamper
}

func TestSign(t *testing.T) {
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	intermediate, intermediatePriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	leaf, leafPriv, err := createLeaf(intermediate, intermediatePriv)
	require.NoError(t, err)
	xs, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf))
	require.NoError(t, err)
	xv, err := xs.Verifier()
	require.NoError(t, err)

	ts := []testTimestamper{
		{true, timestamp.FakeTimestamper{T: time.Now()}},
		{true, timestamp.FakeTimestamper{T: time.Now().Add(12 * time.Hour)}},
		{false, timestamp.FakeTimestamper{T: time.Now().Add(36 * time.Hour)}},
		{false, timestamp.FakeTimestamper{T: time.Now().Add(128 * time.Hour)}},
	}

	testCases := []struct {
		name         string
		bodyType     string
		data         string
		signers      []cryptoutil.Signer
		timestampers []testTimestamper
		verifiers    []cryptoutil.Verifier
		wantSignErr  bool
		failVerify   bool
	}{
		{
			name:         "successful with timestamp",
			bodyType:     "dummytype",
			data:         "dummydata",
			signers:      []cryptoutil.Signer{xs},
			verifiers:    []cryptoutil.Verifier{xv},
			timestampers: ts,
			wantSignErr:  false,
			failVerify:   false,
		},
	}

	for _, tc := range testCases {
		require.NoError(t, err)

		var env Envelope
		var err error
		var timestampVerifiers []timestamp.TimestampVerifier
		if len(tc.timestampers) > 0 {
			timestampers := []timestamp.Timestamper{}
			for _, timestamper := range tc.timestampers {
				if timestamper.expect {
					timestampers = append(timestampers, timestamper.ts)

					// We also want to add it as a verifier for later
					ts, ok := timestamper.ts.(timestamp.FakeTimestamper)
					if !ok {
						t.Fatalf("expected timestamp.FakeTimestamper, got %T", timestamper.ts)
					}
					timestampVerifiers = append(timestampVerifiers, ts)
				}
			}
			env, err = Sign(tc.bodyType, bytes.NewReader([]byte("this is some dummy data")), SignWithSigners(tc.signers...), SignWithTimestampers(timestampers...))
		} else {
			env, err = Sign(tc.bodyType, bytes.NewReader([]byte("this is some dummy data")), SignWithSigners(tc.signers...))
		}

		if tc.wantSignErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}

		var approvedVerifiers []PassedVerifier
		if len(tc.timestampers) > 0 {
			timestampers := []timestamp.TimestampVerifier{}
			for _, timestamper := range tc.timestampers {
				ts, ok := timestamper.ts.(timestamp.FakeTimestamper)
				if !ok {
					t.Fatalf("expected timestamp.FakeTimestamper, got %T", timestamper.ts)
				}
				timestampers = append(timestampers, ts)
			}
			approvedVerifiers, err = env.Verify(VerifyWithVerifiers(tc.verifiers...), VerifyWithTimestampVerifiers(timestampers...))
		} else {
			approvedVerifiers, err = env.Verify(VerifyWithVerifiers(tc.verifiers...))
		}

		if tc.failVerify {
			assert.Empty(t, approvedVerifiers, fmt.Sprintf("test name: %s", tc.name))
		} else if err != nil {
			t.Fatalf("TEST_NAME: %s, ERROR: verify returned an error: %v", tc.name, err)
		}

		if len(tc.timestampers) > 0 {
			for _, v := range approvedVerifiers {
				assert.Equal(t, len(timestampVerifiers), len(v.PassedTimestampVerifiers), fmt.Sprintf("test name: %s", tc.name))
			}
		}

		pv := []PassedVerifier{}
		for _, v := range tc.verifiers {
			pv = append(pv, PassedVerifier{Verifier: v, PassedTimestampVerifiers: timestampVerifiers})
		}
		assert.ElementsMatch(t, approvedVerifiers, pv)

		assert.Equal(t, len(tc.verifiers), len(approvedVerifiers))
	}
}
