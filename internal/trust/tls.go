package trust

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"errors"
	"io"
)

const clientCertificateVerifyPrefix = "                                                                TLS 1.3, client CertificateVerify\x00"

// SignTLSClientMessage is the executor's narrow Ed25519 signing boundary.
// It accepts TLS 1.3's unhashed CertificateVerify message, never arbitrary digests
// or caller-selected signature contexts. It does not authorize the remote peer.
func SignTLSClientMessage(key ed25519.PrivateKey, message []byte) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid TLS signing key")
	}
	if (len(message) != len(clientCertificateVerifyPrefix)+32 && len(message) != len(clientCertificateVerifyPrefix)+48) || !bytes.HasPrefix(message, []byte(clientCertificateVerifyPrefix)) {
		return nil, errors.New("not a TLS 1.3 client CertificateVerify message")
	}
	return ed25519.Sign(key, message), nil
}

// TLSMessageSigner transports a message-aware signing request to the executor.
// The callback must bind its context/deadline and selected stored-key identifier;
// the executor independently enforces SignTLSClientMessage's domain restriction.
type TLSMessageSigner struct {
	public ed25519.PublicKey
	sign   func([]byte) ([]byte, error)
}

var _ crypto.MessageSigner = (*TLSMessageSigner)(nil)

func NewTLSMessageSigner(public ed25519.PublicKey, sign func([]byte) ([]byte, error)) (*TLSMessageSigner, error) {
	if len(public) != ed25519.PublicKeySize || sign == nil {
		return nil, errors.New("invalid TLS message signer")
	}
	return &TLSMessageSigner{public: bytes.Clone(public), sign: sign}, nil
}

func (s *TLSMessageSigner) Public() crypto.PublicKey { return s.public }

func (*TLSMessageSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("prehashed signing is not permitted")
}

func (s *TLSMessageSigner) SignMessage(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if specific, ok := opts.(*ed25519.Options); ok && (specific == nil || specific.Context != "") {
		return nil, errors.New("Ed25519 contexts are not permitted")
	}
	if opts == nil || opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("only pure Ed25519 TLS signing is permitted")
	}
	return s.sign(message)
}
