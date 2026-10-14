// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

// Artifacts names existing local files. Checksum is a signed vendor checksum or
// a sanitized vendor acquisition receipt. Signature is only for detached mode.
// VerifyArtifacts is entirely offline and never modifies these files.
type Artifacts struct {
	Image     string
	Checksum  string
	Signature string
	Key       string
}

// VerifiedImage records bytes and signer actually verified, not a cache-name
// assumption. Callers must use disposable overlays rather than modify Path.
type VerifiedImage struct {
	Path               string
	SHA256             string
	Size               int64
	SigningFingerprint string
	PrimaryFingerprint string
}

type verifiedMetadata struct {
	signing string
	primary string
	digest  string
}

func detachedChecksum(mode labv1.ChecksumMode) bool {
	return mode == labv1.ChecksumMode_CHECKSUM_MODE_DETACHED || mode == labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_SHA512 || mode == labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_IMAGE
}

// VerifyArtifacts checks pinned image bytes and the manifest's explicit trust
// mode offline. Vendor-authenticated receipts do not constitute a signature.
func VerifyArtifacts(ctx context.Context, m *labv1.ImageManifest, files Artifacts) (*VerifiedImage, error) {
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	checksum, err := readRegular(files.Checksum, maxMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("read checksum: %w", err)
	}
	if m.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_VENDOR_AUTHENTICATED {
		if err := verifyVendorReceipt(m, checksum); err != nil {
			return nil, err
		}
		return verifyImage(ctx, m, files.Image, verifiedMetadata{})
	}
	key, err := readRegular(files.Key, maxMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	var signature []byte
	if detachedChecksum(m.ChecksumMode) {
		signature, err = readRegular(files.Signature, maxMetadataBytes)
		if err != nil {
			return nil, fmt.Errorf("read checksum signature: %w", err)
		}
	}
	if m.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_IMAGE {
		return verifySignedImage(ctx, m, files.Image, checksum, signature, key)
	}
	metadata, err := verifyMetadata(ctx, m, checksum, signature, key)
	if err != nil {
		return nil, err
	}
	return verifyImage(ctx, m, files.Image, metadata)
}

// verifySignedImage authenticates a detached OpenPGP signature over the image
// bytes themselves. One streaming read feeds both gpgv and the SHA-256 pin, so
// the signed bytes and the pinned bytes are the same bytes. The vendor's
// unsigned SHA-256 sidecar must agree with the pin; it is never trusted alone.
func verifySignedImage(ctx context.Context, m *labv1.ImageManifest, imagePath string, checksum, signature, key []byte) (_ *VerifiedImage, err error) {
	if _, err := selectedChecksum(checksum, m); err != nil {
		return nil, fmt.Errorf("unsigned vendor SHA-256 sidecar: %w", err)
	}
	file, err := openRegular(imagePath)
	if err != nil {
		return nil, fmt.Errorf("open image: %w", err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() != int64(m.ImageSizeBytes) {
		return nil, fmt.Errorf("image size %d does not match pinned %d bytes", info.Size(), m.ImageSizeBytes)
	}
	pinnedHash := sha256.New()
	var count byteCounter
	image := io.TeeReader(io.LimitReader(contextReader{ctx: ctx, reader: file}, int64(m.ImageSizeBytes)+1), io.MultiWriter(pinnedHash, &count))
	signing, primary, err := verifyStreamSignature(ctx, m.SignerFingerprint, signature, key, image)
	if err != nil {
		return nil, err
	}
	actual := hex.EncodeToString(pinnedHash.Sum(nil))
	if int64(count) != int64(m.ImageSizeBytes) || actual != m.Sha256 {
		return nil, fmt.Errorf("image bytes do not match pinned SHA-256 %s and size", m.Sha256)
	}
	absolute, err := filepath.Abs(imagePath)
	if err != nil {
		return nil, err
	}
	return &VerifiedImage{Path: absolute, SHA256: actual, Size: int64(count), SigningFingerprint: signing, PrimaryFingerprint: primary}, nil
}

type byteCounter int64

func (c *byteCounter) Write(p []byte) (int, error) {
	*c += byteCounter(len(p))
	return len(p), nil
}

// verifyStreamSignature runs gpgv over data read from image on its stdin; the
// caller hashes the same bytes as gpgv consumes them.
func verifyStreamSignature(ctx context.Context, fingerprint string, signature, key []byte, image io.Reader) (signing, primary string, err error) {
	keyring, err := publicKeyring(key)
	if err != nil {
		return "", "", fmt.Errorf("decode public key: %w", err)
	}
	dir, err := os.MkdirTemp("", "lindm-image-verify-")
	if err != nil {
		return "", "", err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
	for name, content := range map[string][]byte{"keyring.gpg": keyring, "signature": signature} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
			return "", "", err
		}
	}
	stdout, stderr := nativeexec.NewBuffer(64<<10), nativeexec.NewBuffer(64<<10)
	args := []string{"--homedir", dir, "--keyring", filepath.Join(dir, "keyring.gpg"), "--status-fd", "2", filepath.Join(dir, "signature"), "-"}
	err = labexec.Run(ctx, labexec.Command{Path: "gpgv", Args: args, Env: []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "GNUPGHOME=" + dir}, Stdin: image, Stdout: stdout, Stderr: stderr, Timeout: 30 * time.Minute})
	if err == nil && (stdout.Truncated() || stderr.Truncated()) {
		err = errors.New("gpgv output exceeds limit")
	}
	if err != nil {
		return "", "", fmt.Errorf("verify image signature with gpgv: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return validSigner(stderr.String(), fingerprint)
}

func verifyImage(ctx context.Context, m *labv1.ImageManifest, imagePath string, metadata verifiedMetadata) (*VerifiedImage, error) {
	file, err := openRegular(imagePath)
	if err != nil {
		return nil, fmt.Errorf("open image: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() != int64(m.ImageSizeBytes) {
		return nil, fmt.Errorf("image size %d does not match pinned %d bytes", info.Size(), m.ImageSizeBytes)
	}
	pinnedHash := sha256.New()
	var signedHash hash.Hash
	var sink io.Writer = pinnedHash
	if m.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_SHA512 {
		signedHash = sha512.New()
		sink = io.MultiWriter(pinnedHash, signedHash)
	}
	count, err := io.Copy(sink, io.LimitReader(contextReader{ctx: ctx, reader: file}, int64(m.ImageSizeBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("hash image: %w", err)
	}
	actual := hex.EncodeToString(pinnedHash.Sum(nil))
	if count != int64(m.ImageSizeBytes) || actual != m.Sha256 {
		return nil, fmt.Errorf("image bytes do not match pinned SHA-256 %s and size", m.Sha256)
	}
	if signedHash != nil && hex.EncodeToString(signedHash.Sum(nil)) != metadata.digest {
		return nil, errors.New("image bytes do not match signed SHA-512 checksum")
	}
	absolute, err := filepath.Abs(imagePath)
	if err != nil {
		return nil, err
	}
	return &VerifiedImage{Path: absolute, SHA256: actual, Size: count, SigningFingerprint: metadata.signing, PrimaryFingerprint: metadata.primary}, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func verifyMetadata(ctx context.Context, m *labv1.ImageManifest, checksum, signature, key []byte) (result verifiedMetadata, err error) {
	result.signing, result.primary, checksum, err = verifySignedBytes(ctx, m.SignerFingerprint, m.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_CLEARSIGNED, checksum, signature, key)
	if err != nil {
		return result, err
	}
	result.digest, err = selectedChecksum(checksum, m)
	return result, err
}

// verifySignedBytes checks a detached or clear signature by the pinned full
// fingerprint and returns the signed plaintext.
func verifySignedBytes(ctx context.Context, fingerprint string, clearsigned bool, data, signature, key []byte) (signing, primary string, plaintext []byte, err error) {
	keyring, err := publicKeyring(key)
	if err != nil {
		return "", "", nil, fmt.Errorf("decode public key: %w", err)
	}
	dir, err := os.MkdirTemp("", "lindm-image-verify-")
	if err != nil {
		return "", "", nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
	for name, content := range map[string][]byte{"keyring.gpg": keyring, "checksums": data, "signature": signature} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
			return "", "", nil, err
		}
	}
	args := []string{"--homedir", dir, "--keyring", filepath.Join(dir, "keyring.gpg"), "--status-fd", "2"}
	if clearsigned {
		args = append(args, "--output", "-", filepath.Join(dir, "checksums"))
	} else {
		args = append(args, filepath.Join(dir, "signature"), filepath.Join(dir, "checksums"))
	}
	stdout, stderr := nativeexec.NewBuffer(maxMetadataBytes), nativeexec.NewBuffer(64<<10)
	err = labexec.Run(ctx, labexec.Command{Path: "gpgv", Args: args, Env: []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "GNUPGHOME=" + dir}, Stdout: stdout, Stderr: stderr, Timeout: 30 * time.Second})
	if err == nil && (stdout.Truncated() || stderr.Truncated()) {
		err = errors.New("gpgv output exceeds limit")
	}
	if err != nil {
		return "", "", nil, fmt.Errorf("verify checksum signature with gpgv: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	signing, primary, err = validSigner(stderr.String(), fingerprint)
	if err != nil {
		return "", "", nil, err
	}
	if clearsigned {
		return signing, primary, stdout.Bytes(), nil
	}
	return signing, primary, data, nil
}

func validSigner(status, pinned string) (string, string, error) {
	var signing, primary string
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "[GNUPG:]" {
			continue
		}
		switch fields[1] {
		case "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYREVOKED", "KEYEXPIRED", "SIGEXPIRED", "NO_PUBKEY", "FAILURE", "ERROR", "NODATA":
			return "", "", fmt.Errorf("gpgv rejected checksum signature: %s", fields[1])
		case "VALIDSIG":
			if len(fields) < 11 || signing != "" {
				return "", "", errors.New("ambiguous or malformed gpgv signature status")
			}
			if fields[9] != "8" && fields[9] != "9" && fields[9] != "10" {
				return "", "", errors.New("checksum signature must use SHA-256, SHA-384 or SHA-512")
			}
			signing, primary = fields[2], fields[2]
			if len(fields) > 11 {
				primary = fields[11]
			}
			if signing != pinned && primary != pinned {
				return "", "", fmt.Errorf("checksum signer %s (primary %s) does not match pinned fingerprint %s", signing, primary, pinned)
			}
		}
	}
	if signing == "" {
		return "", "", errors.New("gpgv did not report a valid pinned checksum signature")
	}
	return signing, primary, nil
}

func selectedChecksum(data []byte, m *labv1.ImageManifest) (string, error) {
	digestSize, algorithm := sha256.Size, "SHA256"
	if m.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_SHA512 {
		digestSize, algorithm = sha512.Size, "SHA512"
	}
	matches := 0
	var selected string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var name, digest string
		if m.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_CLEARSIGNED ||
			(m.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_DETACHED && strings.HasPrefix(line, "SHA256 (")) {
			if !strings.HasPrefix(line, "SHA256 (") {
				return "", errors.New("malformed BSD SHA256 checksum record")
			}
			var found bool
			name, digest, found = strings.Cut(strings.TrimPrefix(line, "SHA256 ("), ") = ")
			if !found {
				return "", errors.New("malformed BSD SHA256 checksum record")
			}
		} else {
			width := digestSize * 2
			if len(line) < width+3 || line[width] != ' ' || (line[width+1] != ' ' && line[width+1] != '*') {
				return "", fmt.Errorf("malformed %sSUMS record", algorithm)
			}
			digest, name = line[:width], line[width+2:]
		}
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != digestSize {
			return "", fmt.Errorf("checksum record has invalid %s digest", algorithm)
		}
		if name == m.ImageFilename {
			matches++
			selected = strings.ToLower(digest)
			if digestSize == sha256.Size && selected != m.Sha256 {
				return "", errors.New("signed image checksum does not match manifest pin")
			}
		}
	}
	if matches != 1 {
		return "", fmt.Errorf("signed checksums must contain exactly one record for %s; found %d", m.ImageFilename, matches)
	}
	return selected, nil
}

// publicKeyring only removes transport armor. All OpenPGP packet parsing, key
// binding, signature verification and trust decisions remain with gpgv and the
// independently pinned full fingerprint. Binary vendor keyrings pass unchanged.
func publicKeyring(data []byte) ([]byte, error) {
	if len(data) > 0 && data[0]&0x80 != 0 {
		return data, nil
	}
	const begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	const end = "-----END PGP PUBLIC KEY BLOCK-----"
	remaining := strings.TrimSpace(string(data))
	var result []byte
	for remaining != "" {
		if !strings.HasPrefix(remaining, begin) {
			return nil, errors.New("expected OpenPGP public key armor")
		}
		body, rest, found := strings.Cut(strings.TrimPrefix(remaining, begin), end)
		if !found {
			return nil, errors.New("unterminated OpenPGP public key armor")
		}
		body = strings.ReplaceAll(body, "\r\n", "\n")
		_, payload, found := strings.Cut(strings.TrimPrefix(body, "\n"), "\n\n")
		// With no armor headers, the initial empty line terminates the headers.
		if strings.HasPrefix(body, "\n\n") {
			payload, found = body[2:], true
		}
		if !found {
			return nil, errors.New("malformed public key armor headers")
		}
		var encoded strings.Builder
		var crc string
		for _, line := range strings.Split(strings.TrimSpace(payload), "\n") {
			if strings.HasPrefix(line, "=") {
				if crc != "" {
					return nil, errors.New("duplicate public key armor checksum")
				}
				crc = line[1:]
			} else {
				if crc != "" {
					return nil, errors.New("data follows public key armor checksum")
				}
				encoded.WriteString(line)
			}
		}
		packet, err := base64.StdEncoding.Strict().DecodeString(encoded.String())
		if err != nil || len(packet) == 0 {
			return nil, errors.New("invalid public key armor payload")
		}
		if crc != "" {
			value, err := base64.StdEncoding.Strict().DecodeString(crc)
			if err != nil || len(value) != 3 || uint32(value[0])<<16|uint32(value[1])<<8|uint32(value[2]) != crc24(packet) {
				return nil, errors.New("invalid public key armor checksum")
			}
		}
		result = append(result, packet...)
		remaining = strings.TrimSpace(rest)
	}
	if len(result) == 0 {
		return nil, errors.New("public key is empty")
	}
	return result, nil
}

func crc24(data []byte) uint32 {
	crc := uint32(0xb704ce)
	for _, b := range data {
		crc ^= uint32(b) << 16
		for range 8 {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864cfb
			}
		}
	}
	return crc & 0xffffff
}
