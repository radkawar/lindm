// Package privatecustody encrypts bounded private native evidence with a durable
// installation key outside SQLite. It does not authorize effects or export keys.
package privatecustody

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/statefs"
	"lindm/internal/protodata"
)

const KeyFileName = "private-custody.key"
const MaximumPlaintextBytes = 4 << 20

var ErrCustody = errors.New("private_custody_recovery_hold")

// Custody uses independent random AES and equality-HMAC keys. Key material is
// never serialized into an evidence envelope. Close invalidates future calls.
// Production callers require root; tests can use a protected current-UID dir.
type Custody struct {
	mu             sync.Mutex
	key            [64]byte
	keyID          [32]byte
	installationID string
	closed         bool
}

// Initialize exclusively creates a key for a new protected installation. Never
// call it to repair an existing installation whose key is missing or corrupt.
func Initialize(directory, installationID string) (*Custody, error) {
	return open(directory, installationID, true)
}

// Open requires the existing protected key, even for an empty journal. It never
// regenerates keys and rejects symlinks, hardlinks, modes and malformed content.
func Open(directory, installationID string) (*Custody, error) {
	return open(directory, installationID, false)
}

// OpenLocal opens the installation's existing key without opening SQLite. The
// immutable protected installation marker, not caller input or a key header
// alone, selects the expected installation identity for native helper processes.
func OpenLocal(directory string) (_ *Custody, resultErr error) {
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return nil, ErrCustody
	}
	dir := os.NewFile(uintptr(fd), "private-custody-directory")
	defer func() { resultErr = errors.Join(resultErr, dir.Close()) }()
	markerFD, err := unix.Openat(fd, "installation", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrCustody
	}
	marker := os.NewFile(uintptr(markerFD), "private-custody-installation")
	defer func() { resultErr = errors.Join(resultErr, marker.Close()) }()
	var stat unix.Stat_t
	if unix.Fstat(markerFD, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Size != 37 {
		return nil, ErrCustody
	}
	var encoded [37]byte
	if _, err := io.ReadFull(marker, encoded[:]); err != nil || encoded[36] != '\n' {
		return nil, ErrCustody
	}
	return Open(directory, string(encoded[:36]))
}

func open(directory, installationID string, create bool) (_ *Custody, resultErr error) {
	id, err := uuid.Parse(installationID)
	if err != nil || id == uuid.Nil || id.String() != installationID {
		return nil, ErrCustody
	}
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return nil, ErrCustody
	}
	dir := os.NewFile(uintptr(fd), "private-custody-directory")
	defer func() { resultErr = errors.Join(resultErr, dir.Close()) }()
	c := &Custody{installationID: installationID}
	defer func() {
		if resultErr != nil {
			c.Close()
		}
	}()
	var encoded [116]byte
	defer clear(encoded[:])
	copy(encoded[:4], "LPC1")
	copy(encoded[4:20], id[:])
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if create {
		if _, err := rand.Read(encoded[20:84]); err != nil {
			return nil, ErrCustody
		}
		checksum := sha256.Sum256(encoded[:84])
		copy(encoded[84:], checksum[:])
		flags = unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW
	}
	keyFD, err := unix.Openat(fd, KeyFileName, flags, 0600)
	if err != nil {
		return nil, ErrCustody
	}
	file := os.NewFile(uintptr(keyFD), "private-custody-key")
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	var stat unix.Stat_t
	if unix.Fstat(keyFD, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, ErrCustody
	}
	if create {
		if n, err := file.Write(encoded[:]); err != nil || n != len(encoded) {
			return nil, ErrCustody
		}
		if file.Sync() != nil || dir.Sync() != nil {
			return nil, ErrCustody
		}
	} else {
		if stat.Size != int64(len(encoded)) {
			return nil, ErrCustody
		}
		if _, err := io.ReadFull(file, encoded[:]); err != nil {
			return nil, ErrCustody
		}
		if string(encoded[:4]) != "LPC1" || !hmac.Equal(encoded[4:20], id[:]) {
			return nil, ErrCustody
		}
	}
	checksum := sha256.Sum256(encoded[:84])
	if !hmac.Equal(checksum[:], encoded[84:]) {
		return nil, ErrCustody
	}
	copy(c.key[:], encoded[20:84])
	c.keyID = checksum
	return c, nil
}

// Binding constructs an unambiguous consumer-specific authenticated context.
// Include the protobuf type, object/action ID, revision and snapshot role.
func Binding(fields ...string) []byte {
	size := 0
	for _, field := range fields {
		size += 8 + len(field)
	}
	out := make([]byte, 0, size)
	for _, field := range fields {
		out = binary.BigEndian.AppendUint64(out, uint64(len(field)))
		out = append(out, field...)
	}
	return out
}

func (c *Custody) aad(binding []byte) []byte {
	aad := Binding("lindm.private-custody.aead.v1", c.installationID)
	return append(aad, binding...)
}

func (c *Custody) tag(plaintext, aad []byte) []byte {
	h := hmac.New(sha256.New, c.key[32:])
	_, _ = h.Write([]byte("lindm.private-custody.equality.v1\x00"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(aad)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(aad)
	_, _ = h.Write(plaintext)
	return h.Sum(nil)
}

// Seal returns a fresh random-nonce ciphertext and a keyed equality tag bound
// to the exact consumer context. The caller retains ownership of plaintext.
func (c *Custody) Seal(plaintext, binding []byte) (*agentv1.PrivateCustodyEnvelope, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(plaintext) > MaximumPlaintextBytes || len(binding) == 0 || len(binding) > 16384 {
		return nil, ErrCustody
	}
	block, err := aes.NewCipher(c.key[:32])
	if err != nil {
		return nil, ErrCustody
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCustody
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrCustody
	}
	aad := c.aad(binding)
	return &agentv1.PrivateCustodyEnvelope{FormatVersion: 1, KeyId: append([]byte(nil), c.keyID[:]...), Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, aad), EqualityTag: c.tag(plaintext, aad)}, nil
}

// Open decrypts into a fresh caller-owned buffer. Clear it after use. A changed
// key, context, nonce, ciphertext or equality tag fails without plaintext.
func (c *Custody) Open(envelope *agentv1.PrivateCustodyEnvelope, binding []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || envelope == nil || envelope.GetFormatVersion() != 1 || len(binding) == 0 || len(binding) > 16384 || len(envelope.GetCiphertext()) < 16 || len(envelope.GetCiphertext()) > MaximumPlaintextBytes+16 || len(envelope.GetNonce()) != 12 || len(envelope.GetEqualityTag()) != 32 || !hmac.Equal(envelope.GetKeyId(), c.keyID[:]) || protodata.ValidateClosed(envelope.ProtoReflect()) != nil {
		return nil, ErrCustody
	}
	block, err := aes.NewCipher(c.key[:32])
	if err != nil {
		return nil, ErrCustody
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCustody
	}
	aad := c.aad(binding)
	plaintext, err := aead.Open(nil, envelope.GetNonce(), envelope.GetCiphertext(), aad)
	if err != nil {
		return nil, ErrCustody
	}
	if !hmac.Equal(c.tag(plaintext, aad), envelope.GetEqualityTag()) {
		clear(plaintext)
		return nil, ErrCustody
	}
	return plaintext, nil
}

// Digest returns a keyed private native revision. Domains distinguish database
// files, account identities and other evidence; no low-entropy secret hash is
// exposed to offline guessing through public observations or signed plans.
func (c *Custody) Digest(domain string, contents []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || domain == "" || len(domain) > 1024 || len(contents) > MaximumPlaintextBytes {
		return nil, ErrCustody
	}
	h := hmac.New(sha256.New, c.key[32:])
	_, _ = h.Write(Binding("lindm.private-native-digest.v1", c.installationID, domain))
	_, _ = h.Write(contents)
	return h.Sum(nil), nil
}

func (c *Custody) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.key[:])
	c.closed = true
}
