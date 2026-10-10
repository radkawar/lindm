package labhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/vmlab"
)

// RemoteRun stages one owned SSH or explicitly configured local container run.
// Args contain the VM lane and flags without scheduler -host/-arch flags.
// Records are copied back before exact run-directory cleanup, including failures.
type RemoteRun struct {
	Host           *labv1.LabHost
	Architecture   string
	Repository     string
	Args           []string
	Stdout, Stderr io.Writer
}

// QuoteShell quotes one argument for the explicit remote Bash, never the user's
// login shell. SSH sends a command string, not an argv vector.
func QuoteShell(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func executionCommand(ctx context.Context, alias, script string) *exec.Cmd {
	if alias == "" {
		return exec.CommandContext(ctx, "/bin/bash", "--noprofile", "--norc", "-c", script)
	}
	return exec.CommandContext(ctx, "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "--", alias, "bash -c "+QuoteShell(script))
}

func runOutput(ctx context.Context, alias, script string) (string, error) {
	cmd := executionCommand(ctx, alias, script)
	out := baselineOutput{limit: 1 << 20}
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("remote command: %w: %s", err, out.String())
	}
	if out.exceeded {
		return "", errors.New("remote command output exceeded 1 MiB")
	}
	return strings.TrimSpace(out.String()), nil
}

// FlagValue reads a value flag without interpreting unrelated lane flags.
func FlagValue(args []string, name string) string {
	for i := range args {
		if args[i] == "-"+name || args[i] == "--"+name {
			if i+1 < len(args) {
				return args[i+1]
			}
		}
		if value, ok := strings.CutPrefix(args[i], "-"+name+"="); ok {
			return value
		}
		if value, ok := strings.CutPrefix(args[i], "--"+name+"="); ok {
			return value
		}
	}
	return ""
}

func SetFlag(args []string, name, value string) []string {
	for i := range args {
		if args[i] == "-"+name || args[i] == "--"+name {
			if i+1 < len(args) {
				args[i+1] = value
				return args
			}
		}
		if strings.HasPrefix(args[i], "-"+name+"=") || strings.HasPrefix(args[i], "--"+name+"=") {
			args[i] = "-" + name + "=" + value
			return args
		}
	}
	return append(args, "-"+name+"="+value)
}

func boolFlag(args []string, name string) bool {
	value := false
	for _, arg := range args {
		if arg == "-"+name || arg == "--"+name {
			value = true
		}
		if text, ok := strings.CutPrefix(arg, "-"+name+"="); ok {
			value = text == "true"
		}
		if text, ok := strings.CutPrefix(arg, "--"+name+"="); ok {
			value = text == "true"
		}
	}
	return value
}

func (r RemoteRun) Run(ctx context.Context) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Hour)
	defer cancel()
	root, err := filepath.Abs(r.Repository)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return fmt.Errorf("remote staging requires -repo checkout: %w", err)
	}
	revision, diffDigest, err := sourceProvenance(ctx, root)
	if err != nil {
		return err
	}
	args := append([]string(nil), r.Args...)
	manifestPath := FlagValue(args, "manifest")
	manifest, err := vmlab.LoadManifest(manifestPath)
	if err != nil {
		return err
	}
	manifests := []*labv1.ImageManifest{manifest}
	if recoveryPath := FlagValue(args, "recovery-manifest"); recoveryPath != "" {
		recovery, err := vmlab.LoadManifest(recoveryPath)
		if err != nil {
			return err
		}
		manifests = append(manifests, recovery)
	}
	cache := FlagValue(args, "cache")
	if cache == "" {
		cache = filepath.Join(root, ".cache/lab/images")
	}
	for _, image := range manifests {
		if _, err := (vmlab.Fetcher{}).Fetch(ctx, image, cache); err != nil {
			return err
		}
	}
	local, err := os.MkdirTemp("", "lindm-host-stage-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(local)) }()
	home, err := runOutput(ctx, r.Host.SshAlias, `printf '%s' "$HOME"`)
	if err != nil {
		return err
	}
	work := r.Host.WorkDirectory
	if strings.HasPrefix(work, "~/") {
		work = filepath.Join(home, strings.TrimPrefix(work, "~/"))
	}
	if !filepath.IsAbs(work) {
		return errors.New("remote host work directory must be absolute or ~/ relative")
	}
	remote, err := runOutput(ctx, r.Host.SshAlias, "umask 077; mkdir -p -- "+QuoteShell(filepath.Join(work, "runs"))+" && mktemp -d "+QuoteShell(filepath.Join(work, "runs", "run-XXXXXXXXXX")))
	if err != nil {
		return err
	}
	// Never remove an arbitrary server response as a directory.
	if filepath.Dir(remote) != filepath.Join(work, "runs") || !strings.HasPrefix(filepath.Base(remote), "run-") {
		return errors.New("unexpected remote staging directory")
	}
	preserveRemote := false
	defer func() {
		if preserveRemote {
			err = errors.Join(err, fmt.Errorf("remote evidence/state retained at %s:%s; transport or evidence collection did not finish", r.Host.SshAlias, remote))
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stop()
		_, cleanErr := runOutput(cleanup, r.Host.SshAlias, "rm -rf -- "+QuoteShell(remote))
		err = errors.Join(err, cleanErr)
	}()
	stage := &remoteStage{ctx: ctx, alias: r.Host.SshAlias, local: local, remote: remote, stderr: r.Stderr, copied: make(map[string]string)}
	if err := stage.mkdir(remote+"/bin", remote+"/inputs", remote+"/work", remote+"/records", remote+"/source", remote+"/images"); err != nil {
		return err
	}
	nativeArch := r.Host.Architectures[0]
	type executable struct{ name, arch, command string }
	executables := []executable{{"lab", nativeArch, "./cmd/lab"}}
	guestProbe := remote + "/bin/lab"
	if r.Architecture != nativeArch {
		switch args[1] {
		case "lifecycle", "dispatch", "device-actions", "enroll-unattended", "updates":
			executables = append(executables, executable{"lab-guest", r.Architecture, "./cmd/lab"})
			guestProbe = remote + "/bin/lab-guest"
		}
	}
	switch args[1] {
	case "inspect", "inspect-storage":
		executables = append(executables, executable{"lindm-agent", r.Architecture, "./cmd/lindm-agent"})
	case "dispatch", "device-actions", "enroll-unattended", "lifecycle":
		executables = append(executables, executable{"lindmd", nativeArch, "./cmd/lindmd"})
	}
	for _, item := range executables {
		output := filepath.Join(local, item.name)
		cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", "-X lindm/internal/agent/buildinfo.Version=0.1.0", "-o", output, item.command)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+item.arch)
		cmd.Stdout, cmd.Stderr = r.Stderr, r.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("cross-build %s: %w", item.name, err)
		}
		if err := stage.sync(output, remote+"/bin/"+item.name); err != nil {
			return err
		}
	}
	if err := stage.syncSource(root, remote+"/source/"); err != nil {
		return err
	}
	if args[1] == "inspect-storage" {
		provenance := filepath.Join(local, "provenance")
		sourceURL := (&url.URL{Scheme: "file", Path: root}).String()
		clone := exec.CommandContext(ctx, "git", "clone", "--quiet", "--depth=1", "--", sourceURL, provenance)
		clone.Stdout, clone.Stderr = r.Stderr, r.Stderr
		if err := clone.Run(); err != nil {
			return fmt.Errorf("stage source provenance: %w", err)
		}
		if err := stage.sync(filepath.Join(provenance, ".git")+"/", remote+"/source/.git/"); err != nil {
			return err
		}
	}
	args = SetFlag(args, "repo", remote+"/source")
	if FlagValue(args, "build-repo") != "" {
		args = SetFlag(args, "build-repo", remote+"/source")
	}
	// Inspect/encrypted/services do not accept a repository flag.
	if args[1] == "inspect" || args[1] == "encrypted" || args[1] == "services" {
		args = removeFlag(args, "repo")
	}
	if args[1] == "inspect" || args[1] == "inspect-storage" {
		args = SetFlag(args, "agent", remote+"/bin/lindm-agent")
	}
	if FlagValue(args, "lab") != "" || args[1] == "device-actions" || args[1] == "lifecycle" || args[1] == "dispatch" {
		args = SetFlag(args, "lab", guestProbe)
	}
	if FlagValue(args, "lindmd") != "" || args[1] == "dispatch" || args[1] == "device-actions" || args[1] == "enroll-unattended" {
		args = SetFlag(args, "lindmd", remote+"/bin/lindmd")
	}
	if args[1] == "enroll-unattended" {
		args = SetFlag(args, "lab-binary", guestProbe)
	}
	if args[1] == "device-actions" && FlagValue(args, "architecture") == "" {
		architecture := "x86_64"
		if r.Architecture == "arm64" {
			architecture = "aarch64"
		}
		args = SetFlag(args, "architecture", architecture)
	}
	if args[1] == "dispatch" {
		args = append(args, "-local-authority=true")
	}
	if args[1] == "lifecycle" {
		if !boolFlag(args, "control-plane-trust") {
			return errors.New("remote lifecycle requires -control-plane-trust=true; manual shared-console lanes remain local")
		}
		args = append(args, "-local-authority=true")
		args = SetFlag(args, "lindmd", remote+"/bin/lindmd")
	}
	// Copy only authenticated image entries, never unrelated cache contents.
	markerStaged := false
	for _, image := range manifests {
		if _, existsErr := runOutput(ctx, r.Host.SshAlias, "test -d "+QuoteShell(filepath.Join(work, "images", "sha256-"+image.Sha256))); existsErr != nil {
			if !markerStaged {
				if err := stage.sync(filepath.Join(cache, ".lindm-images"), remote+"/images/.lindm-images"); err != nil {
					return err
				}
				markerStaged = true
			}
			if err := stage.sync(filepath.Join(cache, "sha256-"+image.Sha256)+"/", remote+"/images/sha256-"+image.Sha256+"/"); err != nil {
				return err
			}
		}
	}
	args = SetFlag(args, "cache", remote+"/images")
	if args[1] == "enroll-unattended" {
		args = SetFlag(args, "work", remote+"/work")
	} else {
		args = SetFlag(args, "work-dir", remote+"/work")
	}
	if FlagValue(args, "golden-cache") != "" || args[1] == "encrypted" || args[1] == "inspect-storage" || args[1] == "device-actions" {
		args = SetFlag(args, "golden-cache", filepath.Join(work, "encrypted"))
	}
	for _, name := range []string{"manifest", "recovery-manifest", "public-key", "redhat-token-file", "first-build", "second-build", "apt-repository", "arch-first-repository", "arch-second-repository", "rejections"} {
		value := FlagValue(args, name)
		if value == "" {
			continue
		}
		var destination string
		if strings.Contains(name, "build") || strings.Contains(name, "repository") || name == "rejections" {
			destination, err = stage.record(value)
		} else {
			destination, err = stage.input(value)
		}
		if err != nil {
			return fmt.Errorf("stage -%s: %w", name, err)
		}
		args = SetFlag(args, name, destination)
	}
	outputs := map[string]string{}
	for _, name := range []string{"record", "inventory-record", "diagnostics", "fixture-output"} {
		if value := FlagValue(args, name); value != "" {
			if name != "diagnostics" {
				if _, e := os.Lstat(value); !errors.Is(e, os.ErrNotExist) {
					return fmt.Errorf("-%s destination must not exist", name)
				}
			}
			outputs[name] = value
			args = SetFlag(args, name, remote+"/records/"+name)
			if name == "diagnostics" {
				if err := stage.mkdir(remote + "/records/diagnostics"); err != nil {
					return err
				}
			}
		}
	}
	config, err := protojson.Marshal(&labv1.LabConfig{Hosts: []*labv1.LabHost{r.Host}})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(local, "host.json"), config, 0600); err != nil {
		return err
	}
	if err := stage.sync(filepath.Join(local, "host.json"), remote+"/host.json"); err != nil {
		return err
	}
	argv := []string{remote + "/bin/lab", "host-exec", remote + "/host.json"}
	argv = append(argv, args...)
	command := make([]string, len(argv))
	for i, s := range argv {
		command[i] = QuoteShell(s)
	}
	script := "cd " + QuoteShell(remote+"/source") + " && exec env " + QuoteShell("TMPDIR="+remote+"/work") + " " + strings.Join(command, " ")
	if r.Host.Runtime == "container" {
		container := "lindm-lab-" + filepath.Base(remote)
		defer func() {
			clean, stop := context.WithTimeout(context.Background(), time.Minute)
			defer stop()
			_, e := runOutput(clean, r.Host.SshAlias, "docker rm -f "+QuoteShell(container))
			err = errors.Join(err, e)
		}()
		devices := ""
		if r.Host.Kvm {
			devices = " --device /dev/kvm --group-add \"$(stat -c %g /dev/kvm)\""
		}
		database := ""
		switch args[1] {
		case "dispatch", "device-actions", "updates", "enroll-unattended", "lifecycle":
			database = " --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock --group-add \"$(stat -c %g /var/run/docker.sock)\""
		}
		script = "exec docker run -i --name " + QuoteShell(container) + " --network host --user \"$(id -u):$(id -g)\"" + devices + database + " --mount " + QuoteShell("type=bind,src="+work+",dst="+work) + " --workdir " + QuoteShell(remote+"/source") + " --env " + QuoteShell("TMPDIR="+remote+"/work") + " " + QuoteShell(r.Host.RunnerImage) + " " + strings.Join(command, " ")
	}
	started := time.Now().UTC()
	cmd := executionCommand(ctx, r.Host.SshAlias, script)
	// The open pipe is a lifetime lease. EOF on disconnect cancels the remote
	// worker, which joins VM children and fixture cleanup before releasing flock.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = r.Stdout, r.Stderr
	runErr := cmd.Run()
	var sshExit *exec.ExitError
	if runErr != nil && (!errors.As(runErr, &sshExit) || sshExit.ExitCode() == 255 || sshExit.ExitCode() < 0) {
		preserveRemote = true
	}
	closeErr := stdin.Close()
	if errors.Is(closeErr, os.ErrClosed) {
		closeErr = nil
	}
	err = errors.Join(runErr, closeErr)
	copyCtx, stop := context.WithTimeout(context.Background(), 5*time.Minute)
	defer stop()
	for name, destination := range outputs {
		remotePath := remote + "/records/" + name
		if _, existsErr := runOutput(copyCtx, r.Host.SshAlias, "test -e "+QuoteShell(remotePath)); existsErr != nil {
			if runErr == nil {
				err = errors.Join(err, fmt.Errorf("remote -%s record missing: %w", name, existsErr))
			}
			continue
		}
		target := destination
		if name == "fixture-output" {
			if e := os.Mkdir(destination, 0700); e != nil {
				err = errors.Join(err, e)
				preserveRemote = true
				continue
			}
		}
		if name == "diagnostics" || name == "fixture-output" {
			remotePath += "/"
		} else {
			target = filepath.Join(local, "returned-"+name+".json")
		}
		copyCmd := exec.CommandContext(copyCtx, "rsync", "-a", "--protect-args", "-e", "ssh -o BatchMode=yes -o ConnectTimeout=10", "--", transferPath(r.Host.SshAlias, remotePath), target)
		copyCmd.Stdout, copyCmd.Stderr = r.Stderr, r.Stderr
		if e := copyCmd.Run(); e != nil {
			err = errors.Join(err, e)
			preserveRemote = true
			continue
		}
		if name == "record" {
			if e := annotateRemoteRecord(target, r.Host, started, time.Now().UTC(), revision, diffDigest); e != nil {
				err = errors.Join(err, e)
				preserveRemote = true
				continue
			}
		}
		if name != "diagnostics" && name != "fixture-output" {
			if e := publishRecord(target, destination); e != nil {
				err = errors.Join(err, e)
				preserveRemote = true
			}
		}
	}
	return err
}

func removeFlag(args []string, name string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "-"+name || args[i] == "--"+name {
			i++
			continue
		}
		if strings.HasPrefix(args[i], "-"+name+"=") || strings.HasPrefix(args[i], "--"+name+"=") {
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func annotateRemoteRecord(path string, host *labv1.LabHost, start, end time.Time, revision, diffDigest string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var record map[string]json.RawMessage
	if err = json.Unmarshal(data, &record); err != nil {
		return err
	}
	metadata, err := json.Marshal(map[string]any{"name": host.Name, "transport": host.Transport, "ssh_alias": host.SshAlias, "runtime": host.Runtime, "runner_image": host.RunnerImage, "started_at": start, "finished_at": end, "elapsed_seconds": end.Sub(start).Seconds(), "source_revision": revision, "source_diff_sha256": diffDigest})
	if err != nil {
		return err
	}
	record["lab_host"] = metadata
	data, err = json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

func publishRecord(source, destination string) (err error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, output.Close())
		if err != nil {
			err = errors.Join(err, os.Remove(destination))
		}
	}()
	_, err = io.Copy(output, input)
	if err != nil {
		return err
	}
	return output.Sync()
}

func sourceProvenance(ctx context.Context, root string) (string, string, error) {
	commit := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "HEAD")
	output := baselineOutput{limit: 4096}
	commit.Stdout, commit.Stderr = &output, &output
	if err := commit.Run(); err != nil {
		return "", "", fmt.Errorf("read source revision: %w: %s", err, output.String())
	}
	hash := sha256.New()
	diff := exec.CommandContext(ctx, "git", "-C", root, "diff", "--binary", "HEAD", "--")
	diff.Stdout = hash
	if err := diff.Run(); err != nil {
		return "", "", fmt.Errorf("hash source diff: %w", err)
	}
	return strings.TrimSpace(output.String()), hex.EncodeToString(hash.Sum(nil)), nil
}

type remoteStage struct {
	ctx                  context.Context
	alias, local, remote string
	stderr               io.Writer
	copied               map[string]string
}

func (s *remoteStage) mkdir(paths ...string) error {
	quoted := make([]string, len(paths))
	for i, p := range paths {
		quoted[i] = QuoteShell(p)
	}
	_, err := runOutput(s.ctx, s.alias, "umask 077; mkdir -p -- "+strings.Join(quoted, " "))
	return err
}
func (s *remoteStage) sync(source, destination string) error {
	cmd := exec.CommandContext(s.ctx, "rsync", "-a", "--protect-args", "-e", "ssh -o BatchMode=yes -o ConnectTimeout=10", "--", source, transferPath(s.alias, destination))
	cmd.Stdout, cmd.Stderr = s.stderr, s.stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("stage %s: %w", source, err)
	}
	return nil
}
func (s *remoteStage) syncSource(source, destination string) error {
	cmd := exec.CommandContext(s.ctx, "rsync", "-a", "--protect-args", "--exclude=.git", "--exclude=.cache", "--exclude=artifacts", "--exclude=node_modules", "--exclude=.tools", "-e", "ssh -o BatchMode=yes -o ConnectTimeout=10", "--", source+"/", transferPath(s.alias, destination))
	cmd.Stdout, cmd.Stderr = s.stderr, s.stderr
	return cmd.Run()
}

func transferPath(alias, path string) string {
	if alias == "" {
		return path
	}
	return alias + ":" + path
}
func (s *remoteStage) input(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if target, ok := s.copied[absolute]; ok {
		return target, nil
	}
	for source, target := range s.copied {
		if relative, ok := strings.CutPrefix(absolute, source+string(filepath.Separator)); ok {
			return filepath.Join(target, relative), nil
		}
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", err
	}
	target := s.remote + "/inputs/" + strconv.Itoa(len(s.copied)) + "-" + filepath.Base(absolute)
	s.copied[absolute] = target
	if info.IsDir() {
		absolute += "/"
		target += "/"
	}
	if err := s.sync(absolute, target); err != nil {
		return "", err
	}
	return strings.TrimSuffix(target, "/"), nil
}

// Native package metadata embeds absolute paths. Relocate only its known file
// reference keys, preserving all package digests and signatures for guest-side
// revalidation. Unknown JSON fields remain subject to the lane's strict decoder.
func (s *remoteStage) record(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var value any
	if err = json.Unmarshal(data, &value); err != nil {
		return "", err
	}
	var relocate func(any) error
	relocate = func(value any) error {
		switch v := value.(type) {
		case map[string]any:
			if root, ok := v["root"].(string); ok && root != "" {
				target, e := s.input(root)
				if e != nil {
					return e
				}
				v["root"] = target
			}
			for key, item := range v {
				if key == "root" || key == "tools" {
					continue
				}
				text, ok := item.(string)
				if ok && text != "" && (key == "path" || key == "public_key" || key == "public_key_armor" || key == "signature_path" || key == "binary" || key == "inrelease" || key == "release" || key == "packages" || key == "database" || key == "database_signature" || key == "repomd") {
					target, e := s.input(text)
					if e != nil {
						return e
					}
					v[key] = target
				} else if e := relocate(item); e != nil {
					return e
				}
			}
		case []any:
			for _, item := range v {
				if e := relocate(item); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if err = relocate(value); err != nil {
		return "", err
	}
	data, err = json.Marshal(value)
	if err != nil {
		return "", err
	}
	local, err := os.CreateTemp(s.local, "record-*.json")
	if err != nil {
		return "", err
	}
	_, writeErr := local.Write(data)
	if err = errors.Join(writeErr, local.Close()); err != nil {
		return "", err
	}
	return s.input(local.Name())
}
