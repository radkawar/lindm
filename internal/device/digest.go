package device

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"io"
)

func hashGrant(secret string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("lindm-enrollment-grant-v1\x00"))
	_, _ = h.Write([]byte(secret))
	return h.Sum(nil)
}

func newGrantSecret() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", nil, err
	}
	secret := "lg1_" + base64.RawURLEncoding.EncodeToString(raw)
	return secret, hashGrant(secret), nil
}

func mutationDigest(method string, parts ...string) []byte {
	h := sha256.New()
	writeLenString(h, "lindm-admin-mutation-v1")
	writeLenString(h, method)
	for _, part := range parts {
		writeLenString(h, part)
	}
	return h.Sum(nil)
}

func writeLenString(h io.Writer, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(s))
}

func digestEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}
