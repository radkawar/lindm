// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRedHatStreamAuthenticatesBeforeParserCallback(t *testing.T) {
	original := redHatFixture(t, "rhsa-2024_6783")
	proof := fixture(t, "redhat-rhsa-2024_6783.json.asc")
	checksum := fixture(t, "redhat-rhsa-2024_6783.json.sha256")
	originalDigest := sha256.Sum256(original)
	changed := append(bytes.Clone(original), '\n')
	changedDigest := sha256.Sum256(changed)
	for _, test := range []struct {
		name              string
		body, hash, proof []byte
		pin               []byte
		errorContains     string
	}{
		{"original", original, checksum, proof, originalDigest[:], ""},
		{"wrong-operator-pin", original, checksum, proof, make([]byte, sha256.Size), "checksum mismatch"},
		{"changed-payload", changed, checksum, proof, nil, "checksum mismatch"},
		{"changed-payload-and-checksum", changed, fmt.Appendf(nil, "%x  rhsa-2024_6783.json\n", changedDigest), proof, nil, "verify vendor signature"},
		{"signature-bitflip", original, checksum, flippedSignature(t, proof), nil, "verify vendor signature"},
		{"missing-signature", original, checksum, nil, nil, ""},
		{"missing-checksum", original, nil, proof, nil, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body []byte
				switch r.URL.Path {
				case "/rhsa-2024_6783.json":
					body = test.body
				case "/rhsa-2024_6783.json.sha256":
					body = test.hash
				case "/rhsa-2024_6783.json.asc":
					body = test.proof
				default:
					http.NotFound(w, r)
					return
				}
				if _, err := w.Write(body); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client, err := New(server.Client())
			if err != nil {
				t.Fatal(err)
			}
			config := redHatSource("9.4", "standard")
			config.Url = server.URL + "/rhsa-2024_6783.json"
			config.ExpectedSha256 = test.pin
			calls := 0
			digest := sha256.New()
			artifact, signedAt, err := client.consumeSignedCSAF(t.Context(), config, func(file *os.File) error {
				calls++
				_, err := io.Copy(digest, file)
				return err
			})
			if test.name != "original" {
				if err == nil || artifact != nil || !signedAt.IsZero() || calls != 0 || (test.errorContains != "" && !strings.Contains(err.Error(), test.errorContains)) {
					t.Fatalf("unauthenticated original reached parser: calls=%d artifact=%v signed_at=%s err=%v", calls, artifact, signedAt, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || !bytes.Equal(digest.Sum(nil), originalDigest[:]) || !bytes.Equal(artifact.Sha256, originalDigest[:]) || artifact.Url != config.Url || artifact.SignerFingerprint != redHatFingerprint || !signedAt.Equal(signatureCreation(t, proof)) {
				t.Fatalf("authenticated staged original lost provenance: calls=%d artifact=%v signed_at=%s", calls, artifact, signedAt)
			}
		})
	}
}
