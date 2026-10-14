// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serverdeps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

// These exact public-key bytes are published by Red Hat, not inferred from a
// short RPM key ID. Rotations require a reviewed vendor pin update. Source:
// https://access.redhat.com/security/team/key
const (
	redHatRelease2 = "567E347AD0044ADE55BA8A5F199E2F91FD431D51"
	redHatRelease4 = "FCD355B305707A62DA143AB6E422397E50FE8467A2A95343D246D6276AFEDF8F"
)

func rpmVendorKeyDigest(fingerprint string) string {
	switch fingerprint {
	case redHatRelease2:
		return "d4b2543626bee31d9438d4a31731aae712c072893c7aed8854f16c42fafc742b"
	case redHatRelease4:
		return "9052b2b274842f1b4f40f6e9f4d08691fb8be1ac2483027e12cca61ec68eab8b"
	default:
		return ""
	}
}

// Native OpenPGP v4 key IDs use the fingerprint's low 64 bits; v6 uses the
// high 64 bits (RFC 9580 section 5.5.4). Vendor download aliases are not key IDs.
func rpmVendorKeyID(fingerprint string) string {
	switch fingerprint {
	case redHatRelease2:
		return "199e2f91fd431d51"
	case redHatRelease4:
		return "fcd355b305707a62"
	default:
		return ""
	}
}

func rpmTarget(m *serverdepsv1.Manifest) error {
	if _, err := snapshotTarget(m); err != nil {
		return err
	}
	if m.GetBackend() != serverdepsv1.Backend_BACKEND_RPM {
		return errors.New("serverdeps: RPM backend requires RHEL 9 x86_64")
	}
	if m.GetCustody() != "development-lab" && m.GetCustody() != "entitled-customer-private" {
		return errors.New("serverdeps: RHEL content requires explicit entitled private or development-lab custody")
	}
	return nil
}

// ValidateRPM independently checks native vendor signatures using an isolated
// RPM database containing only exact-pinned vendor key bytes. It does not trust
// the host RPM keyring, enable any repository, or require a fictitious repomd
// detached signature from the RHSM-authenticated vendor metadata service.
func ValidateRPM(ctx context.Context, root *os.File, m *serverdepsv1.Manifest) (err error) {
	if err := rpmTarget(m); err != nil {
		return err
	}
	if err := validateRPMProvenance(root, m); err != nil {
		return err
	}
	stage, err := os.MkdirTemp("", "lindm-serverdeps-rpm-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	return stageRPM(ctx, root, m, stage)
}

func stageRPM(ctx context.Context, root *os.File, m *serverdepsv1.Manifest, stage string) error {
	db := filepath.Join(stage, "rpmdb")
	if err := os.Mkdir(db, 0700); err != nil {
		return err
	}
	if err := labelRPMDatabase(ctx, stage, db); err != nil {
		return err
	}
	if _, err := rpmCommand(ctx, "rpm", []string{"--dbpath", db, "--initdb"}, nil, 30*time.Second); err != nil {
		return err
	}
	keys := map[string]bool{}
	for _, item := range m.GetFiles() {
		if item.GetKind() != serverdepsv1.FileKind_FILE_KIND_KEY {
			continue
		}
		pin := rpmVendorKeyDigest(item.GetSignerFingerprint())
		if pin == "" || pin != item.GetSha256() || item.GetSizeBytes() > 64<<10 || keys[item.GetSignerFingerprint()] {
			return errors.New("serverdeps: RPM key differs from the exact reviewed vendor pin")
		}
		if err := copyRPMRetained(root, item, stage); err != nil {
			return err
		}
		if _, err := rpmCommand(ctx, "rpmkeys", []string{"--dbpath", db, "--import", filepath.Join(stage, item.GetPath())}, nil, 30*time.Second); err != nil {
			return err
		}
		keys[item.GetSignerFingerprint()] = true
	}
	if len(keys) == 0 {
		return errors.New("serverdeps: RPM closure has no pinned vendor keys")
	}
	for _, item := range m.GetFiles() {
		if item.GetKind() != serverdepsv1.FileKind_FILE_KIND_PACKAGE {
			continue
		}
		if !keys[item.GetSignerFingerprint()] || !strings.HasSuffix(item.GetPath(), ".rpm") {
			return errors.New("serverdeps: RPM package has no exact pinned signer")
		}
		if err := copyRPMRetained(root, item, stage); err != nil {
			return err
		}
		path := filepath.Join(stage, item.GetPath())
		out, err := rpmCommand(ctx, "rpmkeys", []string{"--dbpath", db, "--checksig", "--verbose", path}, nil, 30*time.Second)
		if err != nil || !rpmSignatureMatches(out, item.GetSignerFingerprint()) {
			return errors.Join(err, errors.New("serverdeps: native RPM vendor signature verification failed"))
		}
		identity, err := rpmCommand(ctx, "rpm", []string{"--dbpath", db, "-qp", "--queryformat", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}", path}, nil, 30*time.Second)
		if err != nil || identity != item.GetPackageIdentity() {
			return errors.Join(err, errors.New("serverdeps: native RPM identity differs from closure"))
		}
	}
	return nil
}

// Confined native RPM must traverse the private parent before opening the
// keyring. Apply the existing disposable-root pattern: label only this newly
// created parent from / and its database from the actual native database.
// Never disable enforcement or modify host directories, policy or keyrings.
func labelRPMDatabase(ctx context.Context, stage, directory string) error {
	if _, err := os.Stat("/sys/fs/selinux/enforce"); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	reference, err := rpmCommand(ctx, "rpm", []string{"--eval", "%{_dbpath}"}, nil, 30*time.Second)
	if err != nil {
		return err
	}
	reference = strings.TrimSpace(reference)
	if reference != "/var/lib/rpm" && reference != "/usr/lib/sysimage/rpm" {
		return errors.New("serverdeps: unsupported native RPM database label reference")
	}
	if _, err := rpmCommand(ctx, "chcon", []string{"--reference=/", stage}, nil, 30*time.Second); err != nil {
		return err
	}
	_, err = rpmCommand(ctx, "chcon", []string{"--reference=" + reference, directory}, nil, 30*time.Second)
	return err
}

func rpmSignatureMatches(output, fingerprint string) bool {
	keyID := rpmVendorKeyID(fingerprint)
	if keyID == "" {
		return false
	}
	found := false
	for _, line := range strings.Split(strings.ToLower(output), "\n") {
		if strings.Contains(line, ": not ok") || strings.Contains(line, ": nokey") || strings.Contains(line, ": bad") {
			return false
		}
		if !strings.Contains(line, "signature") {
			continue
		}
		if !strings.HasSuffix(strings.TrimSpace(line), ": ok") || (!strings.Contains(line, "key id "+keyID) && !strings.Contains(line, "key id "+keyID[8:])) {
			return false
		}
		found = true
	}
	return found
}

func copyRPMRetained(root *os.File, item *serverdepsv1.File, stage string) (err error) {
	input, err := OpenRetained(root, item)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	path := filepath.Join(stage, item.GetPath())
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, output.Close()) }()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, int64(item.GetSizeBytes())+1))
	if err != nil {
		return err
	}
	if uint64(written) != item.GetSizeBytes() || hex.EncodeToString(hash.Sum(nil)) != item.GetSha256() {
		return errors.New("serverdeps: RPM retained file changed during staging")
	}
	return output.Sync()
}

// InstallRPM uses only copied, digest-checked local RPMs in a private staging
// tree. An empty network namespace denies egress even to package scriptlets;
// disabled repositories/plugins and localpkg_gpgcheck prevent solver fallback.
// This does not bypass SELinux or import customer/lab signing keys.
func InstallRPM(ctx context.Context, repository string, m *serverdepsv1.Manifest) (err error) {
	if os.Geteuid() != 0 {
		return errors.New("serverdeps: offline native RPM install requires root")
	}
	if err := rpmTarget(m); err != nil {
		return err
	}
	root, err := openSnapshotRoot(repository)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if err := validateRPMProvenance(root, m); err != nil {
		return err
	}
	stage, err := os.MkdirTemp("", "lindm-serverdeps-install-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	if err := stageRPM(ctx, root, m, stage); err != nil {
		return err
	}
	var packages []string
	for _, item := range m.GetFiles() {
		if item.GetKind() == serverdepsv1.FileKind_FILE_KIND_PACKAGE {
			packages = append(packages, filepath.Join(stage, item.GetPath()))
		}
	}
	if len(packages) == 0 || len(packages) > int(m.GetMaxPackages()) {
		return errors.New("serverdeps: invalid offline RPM package count")
	}
	slices.Sort(packages)
	args := []string{"--net", "--", "/usr/bin/dnf", "--noplugins", "--disablerepo=*", "--setopt=localpkg_gpgcheck=1", "--setopt=gpgcheck=1", "--setopt=install_weak_deps=False", "--setopt=skip_if_unavailable=False", "-y", "install"}
	args = append(args, packages...)
	_, err = rpmCommand(ctx, "unshare", args, nil, 20*time.Minute)
	return err
}

func rpmCommand(ctx context.Context, program string, args []string, input io.Reader, timeout time.Duration) (string, error) {
	if !filepath.IsAbs(program) {
		program = "/usr/bin/" + program
	}
	out := nativeexec.NewBuffer(8 << 20)
	// In particular, vendor TLS/RHSM diagnostics must never be copied into
	// errors or evidence: configuration and client certificate details are private.
	err := labexec.Run(ctx, labexec.Command{Path: program, Args: args, Stdin: input, Env: []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/root"}, Stdout: out, Timeout: timeout})
	if err != nil {
		return out.String(), fmt.Errorf("serverdeps: native %s operation failed (native diagnostics suppressed): %w", program, err)
	}
	if out.Truncated() {
		return "", errors.New("serverdeps: native RPM output exceeds bound")
	}
	return out.String(), nil
}
