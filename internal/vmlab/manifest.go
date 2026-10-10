// Package vmlab verifies pinned official images and runs isolated native-agent
// observations in disposable VMs. It does not certify complete native lifecycles.
package vmlab

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"syscall"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
)

const maxMetadataBytes = 1 << 20

var manifestValidator, manifestValidatorErr = protovalidate.New(protovalidate.WithMessages(new(labv1.ImageManifest)))

// LoadManifest strictly decodes the protobuf JSON contract and validates its
// declarative constraints before any network or cache access.
func LoadManifest(filename string) (*labv1.ImageManifest, error) {
	data, err := readRegular(filename, maxMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("read image manifest: %w", err)
	}
	manifest := new(labv1.ImageManifest)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, manifest); err != nil {
		return nil, fmt.Errorf("decode image manifest: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func validateManifest(m *labv1.ImageManifest) error {
	if m == nil {
		return errors.New("image manifest is required")
	}
	if manifestValidatorErr != nil {
		return fmt.Errorf("compile image manifest rules: %w", manifestValidatorErr)
	}
	if err := manifestValidator.Validate(m); err != nil {
		return fmt.Errorf("validate image manifest: %w", err)
	}
	for _, raw := range []string{m.ImageUrl, m.ChecksumUrl, m.KeyUrl, m.SignerProvenanceUrl, m.ReleaseProvenanceUrl} {
		if raw == "" {
			continue // Required URLs and vendor-mode omissions are schema-validated.
		}
		if _, err := httpsURL(raw); err != nil {
			return err
		}
	}
	if m.SignatureUrl != nil {
		if _, err := httpsURL(m.GetSignatureUrl()); err != nil {
			return err
		}
	}
	if m.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_VENDOR_AUTHENTICATED {
		return nil // The schema pins the authenticated API locator, not a CDN URL.
	}
	u, err := httpsURL(m.ImageUrl)
	if err != nil {
		return err
	}
	if path.Base(u.Path) != m.ImageFilename {
		return errors.New("image URL basename must equal image_filename")
	}
	return nil
}

func httpsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("expected HTTPS URL without credentials or fragment: %q", raw)
	}
	return u, nil
}

func openRegular(filename string) (*os.File, error) {
	f, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("artifact must be a regular file, not a symlink or device")
	}
	return f, nil
}

func readRegular(filename string, limit int64) (_ []byte, err error) {
	f, err := openRegular(filename)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return readLimited(f, limit)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("artifact exceeds %d bytes", limit)
	}
	return data, nil
}
