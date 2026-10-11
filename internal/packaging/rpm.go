//go:build linux

package packaging

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

func buildRPM(ctx context.Context, work, payload, version string, arch Architecture, epoch int64, key SigningKey, payloadSHA string, staged []stagedFile, p product) (Artifact, error) {
	pass, err := passphraseFile(work, key)
	if err != nil {
		return Artifact{}, err
	}
	spec, err := writeSpec(work, payload, version, arch, epoch, staged, p)
	if err != nil {
		return Artifact{}, err
	}
	gpg, err := lookupTool("gpg")
	if err != nil {
		return Artifact{}, err
	}
	if _, _, err := runTool(ctx, work, toolCmd{
		Name: "rpmbuild",
		Args: []string{
			"-bb", spec,
			"--target", arch.RPM,
			"--define", "_topdir " + filepath.Join(work, "rpm"),
			"--define", "debug_package %{nil}",
			"--define", "_build_id_links none",
			"--define", "__os_install_post /bin/true",
			"--define", "_buildhost localhost",
			"--define", fmt.Sprintf("source_date_epoch %d", epoch),
			"--define", "clamp_mtime_to_source_date_epoch 1",
			"--define", "use_source_date_epoch_as_buildtime 1",
			"--define", "__gpg " + gpg,
		},
		ExtraEnv: []string{"SOURCE_DATE_EPOCH=" + fmt.Sprint(epoch)},
	}); err != nil {
		return Artifact{}, err
	}
	built, err := findOne(filepath.Join(work, "rpm"), ".rpm")
	if err != nil {
		return Artifact{}, err
	}
	unsignedSHA, _, err := hashFile(built)
	if err != nil {
		return Artifact{}, err
	}
	if err := signRPM(ctx, work, built, key, pass, gpg, epoch); err != nil {
		return Artifact{}, err
	}
	if err := verifyRPM(ctx, work, built, version, arch, payloadSHA, key, staged, p); err != nil {
		return Artifact{}, err
	}
	sum, size, err := hashFile(built)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		Product:           p.name,
		Format:            FormatRPM,
		Path:              built,
		SHA256:            sum,
		UnsignedSHA256:    unsignedSHA,
		Size:              size,
		Architecture:      arch,
		Version:           version,
		PayloadSHA256:     payloadSHA,
		Signed:            true,
		SignerFingerprint: key.Fingerprint,
	}, nil
}

func writeSpec(work, payload, version string, arch Architecture, epoch int64, staged []stagedFile, p product) (string, error) {
	var files strings.Builder
	for _, dir := range p.dirs {
		fmt.Fprintf(&files, "%%dir /%s\n", dir)
	}
	for _, file := range staged {
		mode := fmt.Sprintf("%04o", file.Mode)
		line := fmt.Sprintf("%%attr(%s, root, root) /%s\n", mode, file.Rel)
		if file.Conf {
			line = "%config(noreplace) " + line
		}
		files.WriteString(line)
	}
	dependencies, scriptlets := "", ""
	if p.lifecycle != "" {
		dependencies = "Requires: systemd\n"
		scriptlets = fmt.Sprintf(`
%%posttrans
/bin/sh %s configure

%%preun
if [ "$1" -eq 0 ]; then
  /bin/sh %s remove
fi

%%postun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
  /usr/bin/systemctl daemon-reload || :
fi
`, p.lifecycle, p.lifecycle)
	}
	for _, recommended := range p.rpmRecommends {
		dependencies += "Recommends: " + recommended + "\n"
	}
	spec := fmt.Sprintf(`Name: %s
Version: %s
Release: %s
Summary: %s
License: UNLICENSED
ExclusiveArch: %s
%s

%%description
%s

%%install
mkdir -p %%{buildroot}
cp -a %s %%{buildroot}/

%%files
%s
%s`, p.name, version, RPMRelease, p.summary, arch.RPM, dependencies, p.description, rpmShellLiteral(payload+"/."), files.String(), scriptlets)
	path := filepath.Join(work, p.name+".spec")
	if err := writeFile(path, []byte(spec), 0o644, epoch); err != nil {
		return "", err
	}
	return path, nil
}

// RPM expands macros before the shell parses the script, so both layers
// must preserve the payload path as data.
func rpmShellLiteral(value string) string {
	value = strings.ReplaceAll(value, "%", "%%")
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// The caller retains the signer-home guard until all signing and cleanup finish.
func signRPM(ctx context.Context, work, rpmPath string, key SigningKey, pass, gpg string, epoch int64) error {
	signingEpoch, err := rpmSigningEpoch(ctx, work, key, epoch)
	if err != nil {
		return err
	}
	macros := fmt.Sprintf("%%_gpg_name %s!\n%%_gpg_path %s\n%%__gpg %s\n%%_gpg_passphrase_file %s\n%%__gpg_sign_cmd %%{shescape:%%{__gpg}} --no-options --batch --no-tty --faked-system-time %d! --pinentry-mode loopback --passphrase-file %%{shescape:%%{_gpg_passphrase_file}} --homedir %%{shescape:%%{_gpg_path}} --no-armor -u %%{shescape:%%{_gpg_name}} -sbo %%{shescape:%%{__signature_filename}} -- %%{shescape:%%{__plaintext_filename}}\n", key.Fingerprint, key.Home, gpg, pass, signingEpoch)
	macroPath := filepath.Join(work, "rpmmacros")
	if err := writeFile(macroPath, []byte(macros), 0o600, DefaultSourceDateEpoch); err != nil {
		return err
	}
	_, _, err = runTool(ctx, work, toolCmd{
		Name:     "rpmsign",
		Args:     []string{"--load", macroPath, "--addsign", rpmPath},
		ExtraEnv: gpgEnv(key.Home),
	})
	return err
}

// RPM signatures use a deterministic timestamp, never earlier than key creation.
// Check present-day key validity before asking GPG to sign at the payload epoch.
// Pin the primary fingerprint exactly; selecting a newer subkey implicitly would
// change artifact bytes. RSA and EdDSA are deterministic, unlike DSA/ECDSA.
func rpmSigningEpoch(ctx context.Context, work string, key SigningKey, epoch int64) (int64, error) {
	listed, _, err := runTool(ctx, work, toolCmd{
		Name: "gpg",
		Args: []string{"--no-options", "--batch", "--homedir", key.Home, "--with-colons", "--list-keys", key.Fingerprint},
	})
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(listed), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 12 || fields[0] != "pub" {
			continue
		}
		if fields[1] == "r" || fields[1] == "e" || fields[1] == "d" || !strings.Contains(fields[11], "s") {
			return 0, fmt.Errorf("%w: RPM primary key is not currently usable for signing", ErrSigner)
		}
		if fields[3] != "1" && fields[3] != "3" && fields[3] != "22" {
			return 0, fmt.Errorf("%w: reproducible RPM signing requires RSA or EdDSA", ErrSigner)
		}
		created, err := strconv.ParseInt(fields[5], 10, 64)
		if err != nil || created <= 0 {
			return 0, fmt.Errorf("%w: invalid signing-key creation time", ErrSigner)
		}
		return max(epoch, created), nil
	}
	return 0, fmt.Errorf("%w: missing RPM signing key", ErrSigner)
}

func verifyRPM(ctx context.Context, work, rpmPath, version string, arch Architecture, payloadSHA string, key SigningKey, staged []stagedFile, p product) error {
	// rpm interprets \n inside the query format. The argument contains those
	// two characters, not a raw newline.
	stdout, _, err := runTool(ctx, work, toolCmd{
		Name: "rpm",
		Args: []string{"--query", "--package", "--queryformat", "%{NAME}\\n%{VERSION}\\n%{RELEASE}\\n%{ARCH}\\n", rpmPath},
	})
	if err != nil {
		return err
	}
	want := fmt.Sprintf("%s\n%s\n%s\n%s\n", p.name, version, RPMRelease, arch.RPM)
	if string(stdout) != want {
		return fmt.Errorf("%w: rpm identity does not match the request", ErrArtifact)
	}
	list, _, err := runTool(ctx, work, toolCmd{
		Name: "rpm",
		Args: []string{"--query", "--package", "--list", rpmPath},
	})
	if err != nil {
		return err
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(list)), "\n") {
		listed[line] = true
	}
	for _, file := range staged {
		if !listed["/"+file.Rel] {
			return fmt.Errorf("%w: rpm is missing /%s", ErrArtifact, file.Rel)
		}
	}
	extract := filepath.Join(work, "rpm-extract")
	if err := os.Mkdir(extract, 0o700); err != nil {
		return err
	}
	if err := pipeTools(ctx, work, toolCmd{Name: "rpm2cpio", Args: []string{rpmPath}}, toolCmd{
		Name: "cpio",
		Args: []string{"--extract", "--make-directories", "--quiet", "--no-absolute-filenames", "-D", extract},
		Dir:  extract,
	}); err != nil {
		return err
	}
	got, _, err := hashFile(filepath.Join(extract, p.binary[1:]))
	if err != nil {
		return err
	}
	if got != payloadSHA {
		return fmt.Errorf("%w: rpm payload digest does not match the input", ErrArtifact)
	}
	return verifyRPMSignature(ctx, work, rpmPath, key)
}

func verifyRPMSignature(ctx context.Context, work, rpmPath string, key SigningKey) (err error) {
	db, err := os.MkdirTemp(work, "rpmdb-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(db)) }()
	armor := filepath.Join(db, "verify-key.asc")
	exported, _, err := runTool(ctx, work, toolCmd{
		Name:     "gpg",
		Args:     []string{"--no-options", "--batch", "--homedir", key.Home, "--armor", "--export", key.Fingerprint},
		ExtraEnv: gpgEnv(key.Home),
	})
	if err != nil {
		return err
	}
	if err := writeFile(armor, exported, 0o644, DefaultSourceDateEpoch); err != nil {
		return err
	}
	if _, _, err := runTool(ctx, work, toolCmd{
		Name: "rpmkeys",
		Args: []string{"--dbpath", db, "--import", armor},
	}); err != nil {
		return fmt.Errorf("%w: private rpmdb key import failed", ErrArtifact)
	}
	check, _, err := runTool(ctx, work, toolCmd{
		Name: "rpm",
		Args: []string{"--dbpath", db, "-K", rpmPath},
	})
	if err != nil {
		return fmt.Errorf("%w: rpm signature check failed", ErrArtifact)
	}
	status, prefixed := strings.CutPrefix(string(check), rpmPath+": ")
	if !prefixed || strings.TrimSpace(status) != "digests signatures OK" {
		return fmt.Errorf("%w: rpm signature was not verified", ErrArtifact)
	}
	return nil
}

func pipeTools(ctx context.Context, work string, producer, consumer toolCmd) error {
	prodPath, err := lookupTool(producer.Name)
	if err != nil {
		return err
	}
	consPath, err := lookupTool(consumer.Name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, toolDeadline)
	defer cancel()
	read, write, err := os.Pipe()
	if err != nil {
		return err
	}
	env := baseEnv(work)
	consDir := work
	if consumer.Dir != "" {
		consDir = consumer.Dir
	}
	prodErr, consErr := nativeexec.NewBuffer(toolOutputLimit), nativeexec.NewBuffer(toolOutputLimit)
	prod, err := labexec.Start(ctx, labexec.Command{Path: prodPath, Args: producer.Args, Env: env, Dir: work, Stdout: write, Stderr: prodErr})
	closeErr := write.Close()
	if err != nil {
		return errors.Join(err, closeErr, read.Close())
	}
	consRun := labexec.Run(ctx, labexec.Command{Path: consPath, Args: consumer.Args, Env: env, Dir: consDir, Stdin: read, Stderr: consErr})
	// Closing the read end stops a producer that the consumer abandoned.
	closeErr = errors.Join(closeErr, read.Close())
	prodRun := prod.Wait()
	if closeErr != nil {
		return closeErr
	}
	if prodErr.Truncated() || consErr.Truncated() {
		return fmt.Errorf("%w: extract output exceeded limit", ErrArtifact)
	}
	if prodRun != nil || consRun != nil {
		return fmt.Errorf("%w: rpm payload extract failed", ErrArtifact)
	}
	return nil
}

func findOne(root, suffix string) (string, error) {
	var found []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && strings.HasSuffix(path, suffix) {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(found) != 1 {
		return "", fmt.Errorf("%w: expected one %s artifact, found %d", ErrArtifact, suffix, len(found))
	}
	return found[0], nil
}
