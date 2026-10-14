// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

// EncryptedFirmwareOptions pins installed distribution firmware, not a download.
// RPM versions include the epoch (including 0): epoch:version-release.
type EncryptedFirmwareOptions struct {
	Code, Vars, Package, Version string
	SecureBoot                   bool
	// OwnedDBCertificate explicitly adds one public PEM signer to the private
	// run-only db derivative. Package pins and vendor trust remain mandatory.
	OwnedDBCertificate string
}

// EncryptedFirmwareEvidence describes the private initial firmware state. Enrolled
// keys are not proof of enabled Secure Boot: the running guest must attest that.
type EncryptedFirmwareEvidence struct {
	PackageManager           string `json:"package_manager"`
	Package                  string `json:"package"`
	Version                  string `json:"version"`
	CodeSHA256               string `json:"code_sha256"`
	VarsSHA256               string `json:"vars_sha256"`
	CodePath                 string `json:"code_path"`
	VarsPath                 string `json:"vars_path"`
	SecureBoot               bool   `json:"secure_boot"`
	EnrolledKeys             bool   `json:"enrolled_keys"`
	SourceVarsSHA256         string `json:"source_vars_sha256"`
	OwnedDBCertificateSHA256 string `json:"owned_db_certificate_sha256,omitempty"`
	OwnedDBEnrolled          bool   `json:"owned_db_enrolled,omitempty"`
}

// encryptedHostOutput never includes subprocess output in errors: firmware and
// appliance tools can emit private NVRAM or disk metadata on either stream.
func encryptedHostOutput(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) ([]byte, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + dir, "LC_ALL=C", "LIBGUESTFS_BACKEND=direct", "LIBGUESTFS_TMPDIR=" + dir}
	if name == "guestfish" {
		kernel, modules, err := encryptedSuperminPaths()
		if err != nil {
			return nil, err
		}
		if kernel != "" {
			env = append(env, "SUPERMIN_KERNEL="+kernel, "SUPERMIN_MODULES="+modules)
		}
	}
	out := nativeexec.NewBuffer(4 << 20)
	if err := labexec.Run(ctx, labexec.Command{Path: name, Args: args, Env: env, Dir: dir, Stdout: out, Timeout: timeout}); err != nil {
		return nil, fmt.Errorf("encrypted lab %s failed: %w", name, err)
	}
	if out.Truncated() {
		return nil, fmt.Errorf("encrypted lab %s output exceeds limit", name)
	}
	return out.Bytes(), nil
}

func prepareEncryptedFirmware(ctx context.Context, dir string, opts EncryptedFirmwareOptions) (*EncryptedFirmwareEvidence, error) {
	if opts.OwnedDBCertificate != "" && !opts.SecureBoot {
		return nil, errors.New("owned firmware db enrollment requires Secure Boot")
	}
	if opts.Package == "" || strings.HasPrefix(opts.Package, "-") || strings.ContainsAny(opts.Package, "\r\n\t *?[]") || opts.Version == "" {
		return nil, errors.New("encrypted firmware requires an exact package and version")
	}
	if err := encryptedPrivateDir(dir); err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	code, err := filepath.EvalSymlinks(opts.Code)
	if err != nil {
		return nil, fmt.Errorf("resolve firmware code: %w", err)
	}
	vars, err := filepath.EvalSymlinks(opts.Vars)
	if err != nil {
		return nil, fmt.Errorf("resolve firmware variables: %w", err)
	}
	code, err = filepath.Abs(code)
	if err != nil {
		return nil, err
	}
	vars, err = filepath.Abs(vars)
	if err != nil {
		return nil, err
	}
	manager, err := encryptedFirmwarePackage(ctx, dir, opts, code, vars)
	if err != nil {
		return nil, err
	}
	evidence := &EncryptedFirmwareEvidence{PackageManager: manager, Package: opts.Package, Version: opts.Version, SecureBoot: opts.SecureBoot, CodePath: filepath.Join(dir, "firmware-code.fd"), VarsPath: filepath.Join(dir, "nvram.fd")}
	evidence.CodeSHA256, err = copyEncryptedFirmware(ctx, code, evidence.CodePath)
	if err != nil {
		return nil, fmt.Errorf("copy firmware code: %w", err)
	}
	evidence.VarsSHA256, err = copyEncryptedFirmware(ctx, vars, evidence.VarsPath)
	if err != nil {
		return nil, fmt.Errorf("copy firmware variables: %w", err)
	}
	evidence.SourceVarsSHA256 = evidence.VarsSHA256
	if opts.OwnedDBCertificate != "" {
		certificate, err := readOwnedFirmwareCertificate(opts.OwnedDBCertificate)
		if err != nil {
			return nil, err
		}
		if err := enrollOwnedFirmwareDB(ctx, dir, evidence, certificate); err != nil {
			return nil, err
		}
	}
	if opts.SecureBoot && !evidence.OwnedDBEnrolled {
		data, err := encryptedHostOutput(ctx, dir, time.Minute, "virt-fw-vars", "--input", evidence.VarsPath, "--output-json", "/dev/stdout")
		if err != nil {
			return nil, fmt.Errorf("inspect enrolled firmware keys (virt-fw-vars required): %w", err)
		}
		if err := encryptedEnrolledVars(data); err != nil {
			return nil, err
		}
		evidence.EnrolledKeys = true
	}
	return evidence, nil
}

func encryptedPrivateDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("encrypted lab work directory must be a private mode-0700 directory")
	}
	return nil
}

func encryptedFirmwarePackage(ctx context.Context, dir string, opts EncryptedFirmwareOptions, code, vars string) (string, error) {
	// The native package database, rather than PATH ordering on hosts with both
	// tools installed, determines which package manager can establish ownership.
	manager := ""
	if info, err := os.Stat("/var/lib/dpkg/status"); err == nil && info.Mode().IsRegular() {
		manager = "dpkg"
	} else if _, err := exec.LookPath("rpm"); err == nil {
		manager = "rpm"
	} else {
		return "", errors.New("firmware pin requires an installed dpkg or RPM package database")
	}
	var version, files []byte
	var err error
	if manager == "dpkg" {
		version, err = encryptedHostOutput(ctx, dir, time.Minute, "dpkg-query", "-W", "-f=${db:Status-Status}\n${binary:Package}\n${Version}\n", "--", opts.Package)
		if err == nil {
			files, err = encryptedHostOutput(ctx, dir, time.Minute, "dpkg-query", "-L", "--", opts.Package)
		}
	} else {
		version, err = encryptedHostOutput(ctx, dir, time.Minute, "rpm", "-q", "--qf", "installed\n%{NAME}\n%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}\n", "--", opts.Package)
		if err == nil {
			files, err = encryptedHostOutput(ctx, dir, time.Minute, "rpm", "-ql", "--", opts.Package)
		}
	}
	if err != nil {
		return "", fmt.Errorf("query installed firmware package: %w", err)
	}
	if err := matchEncryptedFirmwarePackage(version, files, opts.Package, opts.Version, code, vars); err != nil {
		return "", err
	}
	return manager, nil
}

func matchEncryptedFirmwarePackage(version, files []byte, pkg, pinned, code, vars string) error {
	fields := strings.Split(strings.TrimSpace(string(version)), "\n")
	if len(fields) != 3 || fields[0] != "installed" || fields[1] != pkg || fields[2] != pinned {
		return errors.New("installed firmware package identity or version does not match exact pin")
	}
	var foundCode, foundVars bool
	for line := range strings.SplitSeq(string(files), "\n") {
		foundCode = foundCode || line == code
		foundVars = foundVars || line == vars
	}
	if !foundCode || !foundVars {
		return errors.New("firmware code and variable template must both belong to the pinned package")
	}
	return nil
}

func copyEncryptedFirmware(ctx context.Context, source, destination string) (_ string, err error) {
	src, err := openRegular(source)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, src.Close()) }()
	info, err := src.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() == 0 || info.Size() > 64<<20 {
		return "", errors.New("firmware size outside supported range")
	}
	dst, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, dst.Close()) }()
	digest := sha256.New()
	n, err := copyVMBytes(ctx, io.MultiWriter(dst, digest), src, 64<<20)
	if err != nil {
		return "", err
	}
	if n != info.Size() {
		return "", errors.New("firmware changed while copying")
	}
	if err := dst.Sync(); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func encryptedEnrolledVars(data []byte) error {
	var store struct {
		Version   int `json:"version"`
		Variables []struct {
			Name string `json:"name"`
			GUID string `json:"guid"`
			Data string `json:"data"`
		} `json:"variables"`
	}
	if err := json.Unmarshal(data, &store); err != nil || store.Version != 2 {
		return errors.New("invalid firmware variable inspection response")
	}
	found := make(map[string]bool, 3)
	for _, variable := range store.Variables {
		guid := "8be4df61-93ca-11d2-aa0d-00e098032b8c"
		switch variable.Name {
		case "PK", "KEK":
		case "db":
			guid = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
		default:
			continue
		}
		payload, err := hex.DecodeString(variable.Data)
		if err != nil || len(payload) < 28 || !strings.EqualFold(variable.GUID, guid) || found[variable.Name] {
			return errors.New("invalid enrolled firmware signature database")
		}
		found[variable.Name] = true
	}
	if !found["PK"] || !found["KEK"] || !found["db"] {
		return errors.New("secure boot requires a variable template with enrolled PK, KEK and db")
	}
	return nil
}
