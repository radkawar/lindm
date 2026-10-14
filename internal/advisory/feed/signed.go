// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/platform"
)

const (
	redHatFingerprint  = "77E79ABE93673533ED09EBE2DCE3823597F5EAC4"
	suseFingerprint    = "6B62473BD771517D41E684DFD4439E7EC133994D"
	maxProofBytes      = 64 << 10
	maxArchiveBytes    = 512 << 20
	maxSignedCSAFBytes = 32 << 20
)

// These are reviewed public trust roots, not keys learned from a feed response.
// Source URLs, fingerprints and update policy are retained in keys/provenance.txt.
//
//go:embed keys/*.asc
var vendorRootFiles embed.FS

type vendorTrust struct {
	// The OpenPGP implementation caches verified key bindings; serialize access
	// to its parsed entities when a Client serves concurrent refreshes.
	mu     sync.Mutex
	redHat openpgp.EntityList
	suse   openpgp.EntityList
}

func newVendorTrust() (*vendorTrust, error) {
	t := &vendorTrust{}
	for _, root := range []struct {
		file        string
		fingerprint string
		keys        *openpgp.EntityList
	}{
		{"keys/redhat-product-security.asc", redHatFingerprint, &t.redHat},
		{"keys/suse-security-automation.asc", suseFingerprint, &t.suse},
	} {
		raw, err := vendorRootFiles.ReadFile(root.file)
		if err != nil {
			return nil, fmt.Errorf("feed: read vendor trust root: %w", err)
		}
		keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("feed: parse vendor trust root: %w", err)
		}
		if len(keys) != 1 || strings.ToUpper(hex.EncodeToString(keys[0].PrimaryKey.Fingerprint)) != root.fingerprint || keys[0].PrivateKey != nil {
			return nil, errors.New("feed: embedded vendor trust fingerprint mismatch")
		}
		*root.keys = keys
	}
	return t, nil
}

// signedPublisher selects the vendor trust root from the adapter the source's
// registry release accepts; a compatible rebuild never borrows a vendor key.
func signedPublisher(config *advisoryv1.FeedSource) (string, error) {
	if config == nil {
		return "", errors.New("feed: signed source required")
	}
	adapter, fingerprint := platform.FeedRedHatCSAF, redHatFingerprint
	switch config.GetFormat() {
	case advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF, advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES:
	case advisoryv1.FeedFormat_FEED_FORMAT_SUSE_CSAF:
		adapter, fingerprint = platform.FeedSUSECSAF, suseFingerprint
	default:
		return "", errors.New("feed: format has no vendor signer")
	}
	if _, err := vendorProduct(config, adapter); err != nil {
		return "", fmt.Errorf("feed: signed format does not match vendor distro: %w", err)
	}
	return fingerprint, nil
}

// verify authenticates complete original bytes, never canonicalized JSON/text.
// The timestamp is taken only from the successfully verified signature packet.
func (t *vendorTrust) verify(ctx context.Context, fingerprint string, payload io.Reader, proof []byte, now time.Time) (string, time.Time, error) {
	if t == nil || payload == nil || now.IsZero() || len(proof) == 0 || len(proof) > maxProofBytes {
		return "", time.Time{}, errors.New("feed: invalid signature verification input")
	}
	proof = bytes.TrimSpace(proof)
	const begin = "-----BEGIN PGP SIGNATURE-----"
	const end = "-----END PGP SIGNATURE-----"
	if !bytes.HasPrefix(proof, []byte(begin)) || !bytes.HasSuffix(proof, []byte(end)) || bytes.Count(proof, []byte(begin)) != 1 || bytes.Count(proof, []byte(end)) != 1 {
		return "", time.Time{}, errors.New("feed: one armored detached signature required")
	}
	block, err := armor.Decode(bytes.NewReader(proof))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("feed: decode detached signature: %w", err)
	}
	if block.Type != openpgp.SignatureType {
		return "", time.Time{}, errors.New("feed: invalid detached signature armor type")
	}
	binary, err := boundedRead(block.Body, maxProofBytes)
	if err != nil {
		return "", time.Time{}, err
	}
	packets := bytes.NewReader(binary)
	p, err := packet.Read(packets)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("feed: parse detached signature: %w", err)
	}
	sig, ok := p.(*packet.Signature)
	if !ok || sig.SigType != packet.SigTypeBinary || packets.Len() != 0 {
		return "", time.Time{}, errors.New("feed: exactly one binary detached signature required")
	}
	if sig.CreationTime.IsZero() || sig.CreationTime.After(now) {
		return "", time.Time{}, errors.New("feed: signature creation time is in the future or missing")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", time.Time{}, err
	}
	var keys openpgp.EntityList
	switch fingerprint {
	case redHatFingerprint:
		keys = t.redHat
	case suseFingerprint:
		keys = t.suse
	default:
		return "", time.Time{}, errors.New("feed: untrusted vendor fingerprint")
	}
	cryptoConfig := &packet.Config{Time: func() time.Time { return now }}
	verified, signer, err := openpgp.VerifyDetachedSignature(keys, contextFeedReader{ctx, payload}, bytes.NewReader(binary), cryptoConfig)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("feed: verify vendor signature: %w", err)
	}
	if strings.ToUpper(hex.EncodeToString(signer.PrimaryKey.Fingerprint)) != fingerprint || verified.IssuerKeyId == nil {
		return "", time.Time{}, errors.New("feed: detached signature has wrong vendor signer")
	}
	// Verification checks bindings at signing time. Also require the exact
	// signing key to remain non-revoked and valid at refresh time.
	key, ok := signer.SigningKeyById(now, *verified.IssuerKeyId, cryptoConfig)
	if !ok {
		return "", time.Time{}, errors.New("feed: vendor signing key is revoked, expired, or invalid")
	}
	return strings.ToUpper(hex.EncodeToString(key.PublicKey.Fingerprint)), verified.CreationTime, nil
}

type contextFeedReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextFeedReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// vendorChecksum accepts the single sha256sum record published next to a CSAF
// artifact. The record must name this exact basename, not a path or another file.
func vendorChecksum(raw []byte, location string) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxProofBytes {
		return nil, errors.New("feed: invalid vendor checksum size")
	}
	u, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("feed: parse checksum artifact URL: %w", err)
	}
	line := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if len(line) < 67 || line[64] != ' ' || (line[65] != ' ' && line[65] != '*') || line[66:] != path.Base(u.Path) || strings.ContainsAny(line, "\r\n") {
		return nil, errors.New("feed: vendor checksum must name the exact artifact")
	}
	digest, err := hex.DecodeString(line[:64])
	if err != nil {
		return nil, fmt.Errorf("feed: invalid vendor SHA256: %w", err)
	}
	return digest, nil
}

// fetchSignedCSAF retains bounded SUSE acquisition; large RHEL originals use
// consumeSignedCSAF. Both vendor proofs remain mandatory on HTTPS mirrors.
func (c *Client) fetchSignedCSAF(ctx context.Context, config *advisoryv1.FeedSource) ([]byte, *advisoryv1.FeedArtifact, time.Time, error) {
	fingerprint, err := signedPublisher(config)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	if config.GetFormat() != advisoryv1.FeedFormat_FEED_FORMAT_SUSE_CSAF {
		return nil, nil, time.Time{}, errors.New("feed: non-SUSE source requires streaming acquisition")
	}
	u, err := signedArtifactURL(config.GetUrl())
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	if !strings.HasSuffix(u.Path, ".json") {
		return nil, nil, time.Time{}, errors.New("feed: signed CSAF URL must name a JSON document")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	location := u.String()
	raw, err := c.get(ctx, location, maxSignedCSAFBytes)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	checksum, signature, err := c.fetchVendorProofs(ctx, location)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(digest[:], checksum) {
		return nil, nil, time.Time{}, errors.New("feed: vendor CSAF checksum mismatch")
	}
	if pin := config.GetExpectedSha256(); len(pin) != 0 && !bytes.Equal(pin, digest[:]) {
		return nil, nil, time.Time{}, errors.New("feed: source checksum mismatch")
	}
	signer, signedAt, err := c.signedTrust.verify(ctx, fingerprint, bytes.NewReader(raw), signature, time.Now())
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	return raw, &advisoryv1.FeedArtifact{Url: location, Sha256: digest[:], SignerFingerprint: signer}, signedAt, nil
}

// consumeSignedCSAF stages a large RHEL document without retaining its original
// bytes in memory. The parser receives the same file only after both vendor
// proofs and any configured digest pin have authenticated the entire payload.
func (c *Client) consumeSignedCSAF(ctx context.Context, config *advisoryv1.FeedSource, consume func(*os.File) error) (artifact *advisoryv1.FeedArtifact, signedAt time.Time, err error) {
	fingerprint, err := signedPublisher(config)
	if err != nil {
		return nil, time.Time{}, err
	}
	if config.GetFormat() != advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF || consume == nil {
		return nil, time.Time{}, errors.New("feed: Red Hat CSAF source and consumer required")
	}
	u, err := signedArtifactURL(config.GetUrl())
	if err != nil {
		return nil, time.Time{}, err
	}
	if !strings.HasSuffix(u.Path, ".json") {
		return nil, time.Time{}, errors.New("feed: signed CSAF URL must name a JSON document")
	}
	location := u.String()
	checksum, signature, err := c.fetchVendorProofs(ctx, location)
	if err != nil {
		return nil, time.Time{}, err
	}
	file, err := os.CreateTemp("", "lindm-feed-csaf-*")
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("feed: stage CSAF: %w", err)
	}
	defer func() {
		err = errors.Join(err, file.Close(), os.Remove(file.Name()))
		if err != nil {
			artifact = nil
			signedAt = time.Time{}
		}
	}()
	digest, err := c.downloadArchive(ctx, location, file, redHatRecordBytes, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	if !bytes.Equal(digest, checksum) {
		return nil, time.Time{}, errors.New("feed: vendor CSAF checksum mismatch")
	}
	if pin := config.GetExpectedSha256(); len(pin) != 0 && !bytes.Equal(pin, digest) {
		return nil, time.Time{}, errors.New("feed: source checksum mismatch")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, time.Time{}, fmt.Errorf("feed: rewind signed CSAF: %w", err)
	}
	signer, signedAt, err := c.signedTrust.verify(ctx, fingerprint, file, signature, time.Now())
	if err != nil {
		return nil, time.Time{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, time.Time{}, fmt.Errorf("feed: rewind verified CSAF: %w", err)
	}
	if err := consume(file); err != nil {
		return nil, time.Time{}, fmt.Errorf("feed: parse verified CSAF: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, time.Time{}, err
	}
	return &advisoryv1.FeedArtifact{Url: location, Sha256: digest, SignerFingerprint: signer}, signedAt, nil
}

func signedArtifactURL(location string) (*url.URL, error) {
	u, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("feed: parse signed artifact URL: %w", err)
	}
	if err := httpsURL(u); err != nil {
		return nil, err
	}
	if u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || strings.Contains(u.Path, "\\") {
		return nil, errors.New("feed: signed artifact URL must be an unescaped path without query")
	}
	return u, nil
}

func (c *Client) fetchVendorProofs(ctx context.Context, location string) ([]byte, []byte, error) {
	raw, err := c.get(ctx, location+".sha256", maxProofBytes)
	if err != nil {
		return nil, nil, err
	}
	checksum, err := vendorChecksum(raw, location)
	if err != nil {
		return nil, nil, err
	}
	signature, err := c.get(ctx, location+".asc", maxProofBytes)
	if err != nil {
		return nil, nil, err
	}
	return checksum, signature, nil
}

// fetchRedHatArchives acquires both complete vendor distributions sequentially.
// Each request retains the HTTP client's two-minute timeout; parsing duration is
// bounded by the caller's progress watchdog and overall ceiling, not here.
// At most one 512 MiB compressed file is staged; its original bytes are verified
// before the parser sees them. Freshness must be bounded by the returned oldest
// signature time, never by the mutable pointer or local download time.
func (c *Client) fetchRedHatArchives(ctx context.Context, config *advisoryv1.FeedSource, consume func(io.Reader, string) error) (*advisoryv1.FeedManifest, time.Time, error) {
	fingerprint, err := signedPublisher(config)
	if err != nil {
		return nil, time.Time{}, err
	}
	if config.GetFormat() != advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES || consume == nil {
		return nil, time.Time{}, errors.New("feed: Red Hat archive source and consumer required")
	}
	root, err := signedArtifactURL(config.GetUrl())
	if err != nil {
		return nil, time.Time{}, err
	}
	root.Path = strings.TrimSuffix(root.Path, "/")
	if root.Path != "" && path.Clean(root.Path) != root.Path {
		return nil, time.Time{}, errors.New("feed: archive provider root is not a confined path")
	}
	manifest := &advisoryv1.FeedManifest{Artifacts: make([]*advisoryv1.FeedArtifact, 0, 2)}
	var oldest time.Time
	for _, distribution := range []string{"advisories", "vex"} {
		directory := *root
		directory.Path += "/" + distribution + "/"
		latest := directory
		latest.Path += "archive_latest.txt"
		pointer, err := c.get(ctx, latest.String(), 4096)
		if err != nil {
			return nil, time.Time{}, err
		}
		name, err := redHatArchiveName(pointer, distribution)
		if err != nil {
			return nil, time.Time{}, err
		}
		archive := directory
		archive.Path += name
		artifact, signedAt, err := c.consumeSignedArchive(ctx, archive.String(), fingerprint, consume)
		if err != nil {
			return nil, time.Time{}, err
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
		if oldest.IsZero() || signedAt.Before(oldest) {
			oldest = signedAt
		}
	}
	return manifest, oldest, nil
}

func redHatArchiveName(raw []byte, distribution string) (string, error) {
	name := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	prefix := "csaf_" + distribution + "_"
	const suffix = ".tar.zst"
	if len(name) != len(prefix)+len("2006-01-02")+len(suffix) || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return "", errors.New("feed: invalid confined Red Hat archive basename")
	}
	date := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	if _, err := time.Parse("2006-01-02", date); err != nil {
		return "", fmt.Errorf("feed: invalid archive date: %w", err)
	}
	return name, nil
}

func (c *Client) consumeSignedArchive(ctx context.Context, location, fingerprint string, consume func(io.Reader, string) error) (artifact *advisoryv1.FeedArtifact, signedAt time.Time, err error) {
	checksum, signature, err := c.fetchVendorProofs(ctx, location)
	if err != nil {
		return nil, time.Time{}, err
	}
	file, err := os.CreateTemp("", "lindm-feed-archive-*")
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("feed: stage archive: %w", err)
	}
	defer func() {
		err = errors.Join(err, file.Close(), os.Remove(file.Name()))
		if err != nil {
			artifact = nil
			signedAt = time.Time{}
		}
	}()
	digest, err := c.downloadArchive(ctx, location, file, maxArchiveBytes, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	if !bytes.Equal(digest, checksum) {
		return nil, time.Time{}, errors.New("feed: vendor archive checksum mismatch")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, time.Time{}, fmt.Errorf("feed: rewind signed archive: %w", err)
	}
	signer, signedAt, err := c.signedTrust.verify(ctx, fingerprint, file, signature, time.Now())
	if err != nil {
		return nil, time.Time{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, time.Time{}, fmt.Errorf("feed: rewind verified archive: %w", err)
	}
	if err := consume(contextFeedReader{ctx, file}, location); err != nil {
		return nil, time.Time{}, fmt.Errorf("feed: parse verified archive: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, time.Time{}, err
	}
	return &advisoryv1.FeedArtifact{Url: location, Sha256: digest, SignerFingerprint: signer}, signedAt, nil
}

func (c *Client) downloadArchive(ctx context.Context, location string, file *os.File, bound int64, progress func() error) (digest []byte, err error) {
	u, err := signedArtifactURL(location)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("feed: create archive request: %w", err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.archive.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feed: fetch archive: %w", err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	if resp.TLS == nil || !resp.TLS.HandshakeComplete || len(resp.TLS.VerifiedChains) == 0 {
		return nil, errors.New("feed: archive response lacks verified TLS")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed: archive HTTP status %d", resp.StatusCode)
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, errors.New("feed: unsupported archive HTTP content encoding")
	}
	if resp.ContentLength > bound {
		return nil, errors.New("feed: compressed archive byte limit exceeded")
	}
	digestHasher := sha256.New()
	destination := io.MultiWriter(file, digestHasher)
	var expectedCRC []byte
	for _, header := range resp.Header.Values("X-Goog-Hash") {
		for _, value := range strings.Split(header, ",") {
			if encoded, found := strings.CutPrefix(strings.TrimSpace(value), "crc32c="); found {
				if expectedCRC != nil {
					return nil, errors.New("feed: duplicate archive CRC32C")
				}
				expectedCRC, err = base64.StdEncoding.Strict().DecodeString(encoded)
				if err != nil || len(expectedCRC) != 4 {
					return nil, errors.New("feed: invalid archive CRC32C")
				}
			}
		}
	}
	var checksum hash.Hash32
	if expectedCRC != nil {
		checksum = crc32.New(crc32.MakeTable(crc32.Castagnoli))
		destination = io.MultiWriter(destination, checksum)
	}
	if progress != nil {
		destination = &progressWriter{dst: destination, progress: progress}
	}
	if err := copyArchive(ctx, destination, resp.Body, bound); err != nil {
		return nil, err
	}
	// GCS transfer integrity is additional to TLS and an operator SHA-256 pin,
	// never a substitute for a publisher signature.
	if expectedCRC != nil && !bytes.Equal(expectedCRC, checksum.Sum(nil)) {
		return nil, errors.New("feed: archive CRC32C mismatch")
	}
	return digestHasher.Sum(nil), nil
}

// copyArchive writes no more than bound bytes to disk, probing just one further
// byte from the network to distinguish an exact-bound artifact from overflow.
func copyArchive(ctx context.Context, dst io.Writer, src io.Reader, bound int64) error {
	reader := contextFeedReader{ctx, src}
	if _, err := io.Copy(dst, io.LimitReader(reader, bound)); err != nil {
		return fmt.Errorf("feed: stream archive: %w", err)
	}
	var extra [1]byte
	n, err := io.ReadFull(reader, extra[:])
	if n != 0 {
		return errors.New("feed: compressed archive byte limit exceeded")
	}
	if err != io.EOF {
		return fmt.Errorf("feed: finish archive stream: %w", err)
	}
	return nil
}

// progressWriter reports transfer progress to the refresh watchdog every
// progressBytes, so a slow but advancing download is not treated as stalled.
type progressWriter struct {
	dst      io.Writer
	progress func() error
	pending  int64
}

const progressBytes = 16 << 20

func (w *progressWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	w.pending += int64(n)
	if err == nil && w.pending >= progressBytes {
		w.pending = 0
		err = markProgress(w.progress)
	}
	return n, err
}
