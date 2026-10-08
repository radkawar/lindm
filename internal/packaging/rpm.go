//go:build linux

package packaging

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func buildRPM(ctx context.Context, work, payload, version string, arch Architecture, epoch int64, key SigningKey, payloadSHA string, staged []stagedFile) (Artifact, error) {
	pass, err := passphraseFile(work, key)
	if err != nil {
		return Artifact{}, err
	}
	spec, err := writeSpec(work, payload, version, arch, epoch, staged)
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
	if err := signRPM(ctx, work, built, key, pass, gpg); err != nil {
		return Artifact{}, err
	}
	if err := verifyRPM(ctx, work, built, version, arch, payloadSHA, key, staged); err != nil {
		return Artifact{}, err
	}
	sum, size, err := hashFile(built)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		Format:            FormatRPM,
		Path:              built,
		SHA256:            sum,
		Size:              size,
		Architecture:      arch,
		Version:           version,
		PayloadSHA256:     payloadSHA,
		Signed:            true,
		SignerFingerprint: key.Fingerprint,
	}, nil
}

func writeSpec(work, payload, version string, arch Architecture, epoch int64, staged []stagedFile) (string, error) {
	var files strings.Builder
	files.WriteString("%dir /usr/libexec/lindm\n%dir /etc/lindm\n%dir /usr/share/doc/lindm-agent\n")
	for _, file := range staged {
		mode := fmt.Sprintf("%04o", file.Mode)
		line := fmt.Sprintf("%%attr(%s, root, root) /%s\n", mode, file.Rel)
		if file.Conf {
			line = "%config(noreplace) " + line
		}
		files.WriteString(line)
	}
	spec := fmt.Sprintf(`Name: %s
Version: %s
Release: %s
Summary: Lindm protected agent
License: UNLICENSED
BuildArch: %s
Requires: systemd

%%description
Versioned agent binary with a root executor and an unprivileged network
service. Remove and purge retain identity and spool state. This package
does not grant a root shell.

%%install
mkdir -p %%{buildroot}
cp -a %s %%{buildroot}/

%%files
%s
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
`, PackageName, version, RPMRelease, arch.RPM, rpmShellLiteral(payload+"/."), files.String(), lifecyclePath, lifecyclePath)
	path := filepath.Join(work, "lindm-agent.spec")
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
func signRPM(ctx context.Context, work, rpmPath string, key SigningKey, pass, gpg string) error {
	macros := fmt.Sprintf("%%_gpg_name %s\n%%_gpg_path %s\n%%__gpg %s\n%%_gpg_passphrase_file %s\n%%__gpg_sign_cmd %%{shescape:%%{__gpg}} --no-options --batch --no-tty --pinentry-mode loopback --passphrase-file %%{shescape:%%{_gpg_passphrase_file}} --homedir %%{shescape:%%{_gpg_path}} --no-armor -u %%{shescape:%%{_gpg_name}} -sbo %%{shescape:%%{__signature_filename}} -- %%{shescape:%%{__plaintext_filename}}\n", key.Fingerprint, key.Home, gpg, pass)
	macroPath := filepath.Join(work, "rpmmacros")
	if err := writeFile(macroPath, []byte(macros), 0o600, DefaultSourceDateEpoch); err != nil {
		return err
	}
	_, _, err := runTool(ctx, work, toolCmd{
		Name:     "rpmsign",
		Args:     []string{"--load", macroPath, "--addsign", rpmPath},
		ExtraEnv: gpgEnv(key.Home),
	})
	return err
}

func verifyRPM(ctx context.Context, work, rpmPath, version string, arch Architecture, payloadSHA string, key SigningKey, staged []stagedFile) error {
	// rpm interprets \n inside the query format. The argument contains those
	// two characters, not a raw newline.
	stdout, _, err := runTool(ctx, work, toolCmd{
		Name: "rpm",
		Args: []string{"--query", "--package", "--queryformat", "%{NAME}\\n%{VERSION}\\n%{RELEASE}\\n%{ARCH}\\n", rpmPath},
	})
	if err != nil {
		return err
	}
	want := fmt.Sprintf("%s\n%s\n%s\n%s\n", PackageName, version, RPMRelease, arch.RPM)
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
	got, _, err := hashFile(filepath.Join(extract, BinaryPath[1:]))
	if err != nil {
		return err
	}
	if got != payloadSHA {
		return fmt.Errorf("%w: rpm payload digest does not match the input", ErrArtifact)
	}
	db := filepath.Join(work, "rpmdb")
	if err := os.Mkdir(db, 0o700); err != nil {
		return err
	}
	armor := filepath.Join(work, "verify-key.asc")
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
	text := string(check)
	if strings.Contains(text, "NOT OK") || strings.Contains(text, "NOKEY") || strings.Contains(text, "BAD") || !strings.Contains(text, "signatures OK") {
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
	prod := exec.CommandContext(ctx, prodPath, producer.Args...)
	cons := exec.CommandContext(ctx, consPath, consumer.Args...)
	stdout, err := prod.StdoutPipe()
	if err != nil {
		return err
	}
	cons.Stdin = stdout
	prod.Dir, cons.Dir = work, work
	if consumer.Dir != "" {
		cons.Dir = consumer.Dir
	}
	env := baseEnv(work)
	prod.Env, cons.Env = env, env
	prod.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	prodErr := &limitedWriter{limit: toolOutputLimit}
	consErr := &limitedWriter{limit: toolOutputLimit}
	prod.Stderr, cons.Stderr = prodErr, consErr
	prod.WaitDelay = 2 * time.Second
	cons.WaitDelay = 2 * time.Second
	killGroup := func() {
		if prod.Process != nil {
			_ = syscall.Kill(-prod.Process.Pid, syscall.SIGKILL)
		}
	}
	prod.Cancel = func() error {
		killGroup()
		return os.ErrProcessDone
	}
	if err := prod.Start(); err != nil {
		return err
	}
	cons.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: prod.Process.Pid}
	cons.Cancel = prod.Cancel
	if err := cons.Start(); err != nil {
		killGroup()
		_ = prod.Wait()
		return err
	}
	consErrRun := cons.Wait()
	_ = stdout.Close()
	prodErrRun := prod.Wait()
	if prodErr.exceeded || consErr.exceeded {
		return fmt.Errorf("%w: extract output exceeded limit", ErrArtifact)
	}
	if prodErrRun != nil || consErrRun != nil {
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
