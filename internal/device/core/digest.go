package core

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"io"

	"google.golang.org/protobuf/proto"
)

func HashGrant(secret string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("lindm-enrollment-grant-v1\x00"))
	_, _ = h.Write([]byte(secret))
	return h.Sum(nil)
}

func NewGrantSecret() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", nil, err
	}
	secret := "lg1_" + base64.RawURLEncoding.EncodeToString(raw)
	return secret, HashGrant(secret), nil
}

func MutationDigest(method string, parts ...string) []byte {
	h := sha256.New()
	WriteLenString(h, "lindm-admin-mutation-v1")
	WriteLenString(h, method)
	for _, part := range parts {
		WriteLenString(h, part)
	}
	return h.Sum(nil)
}

func WriteLenString(h io.Writer, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(s))
}

func DigestEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

func ActionDigest(message proto.Message) ([]byte, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}
