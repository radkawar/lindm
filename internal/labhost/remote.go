package labhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/vmlab"
)

// RemoteRun stages one owned SSH or explicitly configured local container run.
// Args contain the VM lane and flags without scheduler -host/-arch flags.
// Records are copied back before exact run-directory cleanup, including failures.
type RemoteRun struct {
	Host         *labv1.LabHost
	Architecture string
	Repository   string
	Args         []string
	Hold         bool
	// BatchCredential is an opaque private handoff from a live whole-host
	// reservation. The worker must receive and validate its held flock.
	BatchCredential string
	// ReverseForwards are "PORT:HOST:PORT" ssh -R entries on the execution
	// connection only: the lab host's 127.0.0.1:PORT (bound explicitly, never
	// ::1) reaches HOST:PORT on the controller for the run's lifetime, and a
	// refused bind fails the run.
	ReverseForwards []string
	// OnHeld is called once, with the run's execution context and the bytes of
	// the private marker the remote lane writes as <evidence>/held, when a held
	// run is ready. The marker is read over ssh without logging, removed
	// remotely and never returned as evidence. The context ends when the
	// remote run does; publish nothing after that. An error cancels the run.
	OnHeld func(ctx context.Context, marker []byte) error
	// OnRegistration is called with each bounded marker a held run's worker
	// writes as <evidence>/registration to have the controller record a
	// vendor registration. The marker is removed remotely only after
	// OnRegistration returns, which acknowledges the durable record to the
	// waiting worker; an error cancels the run. It is polled until held.
	OnRegistration func(ctx context.Context, marker []byte) error
	Stdout, Stderr io.Writer
}

// heldMarker is the remote evidence file that announces a ready held run.
const heldMarker = "held"

// RegistrationMarker is the evidence file in which a held run's worker asks
// its controller to record a registration; its removal is the acknowledgement.
const RegistrationMarker = "registration"

// maxHeldMarker bounds the held and registration markers; they carry small
// JSON only.
const maxHeldMarker = 64 << 10

// QuoteShell quotes one argument for the explicit remote Bash, never the user's
// login shell. SSH sends a command string, not an argv vector.
func QuoteShell(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func executionCommand(ctx context.Context, alias, script string, sshOptions ...string) *exec.Cmd {
	if alias == "" {
		return exec.CommandContext(ctx, "/bin/bash", "--noprofile", "--norc", "-c", script)
	}
	args := append([]string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3"}, sshOptions...)
	return exec.CommandContext(ctx, "ssh", append(args, "--", alias, "bash -c "+QuoteShell(script))...)
}

// cancelByClosingLease is a Cmd.Cancel that ends the worker's stdin lifetime
// lease. The owner may already have closed the lease to stop the worker; that
// is the requested stop, not a cancellation failure.
func cancelByClosingLease(stdin io.Closer) func() error {
	return func() error {
		if err := stdin.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			return err
		}
		return nil
	}
}

// reverseForwardOptions validates "PORT:HOST:PORT" entries (HOST an IP
// literal) and returns ssh options that fail the connection if any remote
// bind is refused.
func reverseForwardOptions(forwards []string) ([]string, error) {
	if len(forwards) == 0 {
		return nil, nil
	}
	options := []string{"-o", "ExitOnForwardFailure=yes"}
	for _, forward := range forwards {
		parts := strings.Split(forward, ":")
		if len(parts) != 3 || net.ParseIP(parts[1]) == nil {
			return nil, fmt.Errorf("reverse forward %q must be PORT:IP:PORT", forward)
		}
		for _, port := range []string{parts[0], parts[2]} {
			if value, err := strconv.ParseUint(port, 10, 16); err != nil || value == 0 {
				return nil, fmt.Errorf("reverse forward %q has an invalid port", forward)
			}
		}
		options = append(options, "-R", "127.0.0.1:"+forward)
	}
	return options, nil
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

func (r RemoteRun) Run(ctx context.Context) (err error) {
	if len(r.Args) >= 2 && r.Args[1] == "assistance" && remoteDestroyRequested(r.Args) {
		return r.destroyAssistance(ctx)
	}
	if len(r.Args) >= 2 && r.Args[1] == "assistance" && r.Host.Runtime != "native" {
		return errors.New("remote assistance requires a native lab host")
	}
	// No controller-side lane deadline: the remote host-exec queues for its
	// own admission and only then starts the lane's deadline, and it ends the
	// lane when this session's stdin closes.
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
	// Staged credentials never outlive the run, even when its state is retained.
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stop()
		_, cleanErr := runOutput(cleanup, r.Host.SshAlias, removeRemoteSecretsCommand(remote))
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
	guestObserver := consoleBrowserLane(args[1])
	switch args[1] {
	case "lifecycle", "dispatch", "resources", "device-actions", "enroll-unattended", "updates", "assistance", "advisories", "airgap":
		guestObserver = true
	}
	if r.Architecture != nativeArch && guestObserver {
		executables = append(executables, executable{"lab-guest", r.Architecture, "./cmd/lab"})
		guestProbe = remote + "/bin/lab-guest"
	}
	switch args[1] {
	case "inspect", "inspect-storage":
		executables = append(executables, executable{"lindm-agent", r.Architecture, "./cmd/lindm-agent"})
	case "dispatch", "resources", "device-actions", "enroll-unattended", "lifecycle", "assistance", "advisories", "airgap":
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
	if FlagValue(args, "lab") != "" || args[1] == "device-actions" || args[1] == "lifecycle" || args[1] == "dispatch" || args[1] == "resources" || args[1] == "assistance" || args[1] == "advisories" {
		args = SetFlag(args, "lab", guestProbe)
	}
	if FlagValue(args, "lindmd") != "" || args[1] == "dispatch" || args[1] == "resources" || args[1] == "device-actions" || args[1] == "enroll-unattended" || args[1] == "assistance" || args[1] == "advisories" {
		args = SetFlag(args, "lindmd", remote+"/bin/lindmd")
	}
	if args[1] == "enroll-unattended" || consoleBrowserLane(args[1]) {
		args = SetFlag(args, "lab-binary", guestProbe)
	}
	if (args[1] == "device-actions" || args[1] == "assistance") && FlagValue(args, "architecture") == "" {
		architecture := "x86_64"
		if r.Architecture == "arm64" {
			architecture = "aarch64"
		}
		args = SetFlag(args, "architecture", architecture)
	}
	if args[1] == "dispatch" || args[1] == "resources" {
		args = append(args, "-local-authority=true")
	}
	if args[1] == "lifecycle" {
		// The shared development console is local-only. Every remote lifecycle
		// variant, including manual trust/service execution, uses a private
		// lindmd with isolated local authority beside the guest.
		args = append(args, "-local-authority=true")
		args = SetFlag(args, "lindmd", remote+"/bin/lindmd")
	}
	// Copy only authenticated image entries, never unrelated cache contents.
	markerStaged := false
	snapshotsStaged := make(map[string]bool)
	for _, image := range manifests {
		if digest := image.GetRepositorySnapshotManifestSha256(); digest != "" && !snapshotsStaged[digest] {
			if err := stageRepositorySnapshot(ctx, r.Host.SshAlias, remote+"/bin/lab", filepath.Join(work, "images"), cache, digest, r.Stderr); err != nil {
				return fmt.Errorf("stage authenticated repository closure: %w", err)
			}
			snapshotsStaged[digest] = true
		}
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
	if FlagValue(args, "golden-cache") != "" || args[1] == "encrypted" || args[1] == "inspect-storage" || args[1] == "device-actions" || args[1] == "assistance" {
		args = SetFlag(args, "golden-cache", filepath.Join(work, "encrypted"))
	}
	if recoveryUkifyLane(args) {
		ukify, err := stage.recoveryUkify(work)
		if err != nil {
			return err
		}
		args = SetFlag(args, "ukify", ukify)
	}
	if name := FlagValue(args, "name"); args[1] == "assistance" && name != "" {
		demo, err := DemoDirectory(work, name)
		if err != nil {
			return err
		}
		args = SetFlag(args, "demo-root", demo)
	}
	if args[1] == "snapshot" {
		if retained := FlagValue(args, "retained-metadata"); retained != "" {
			if len(manifests) != 1 {
				return errors.New("snapshot metadata staging requires one pinned native image")
			}
			if err := stage.stageRepositoryMetadata(manifests[0], args, retained); err != nil {
				return err
			}
			args = SetFlag(args, "retained-metadata", remote+"/snapshot-metadata")
		}
	}
	for _, name := range []string{"manifest", "recovery-manifest", "control-plane", "demo-device", "public-key", "redhat-token-file", "first-build", "second-build", "apt-repository", "arch-first-repository", "arch-second-repository", "rejections", "first-bundle", "second-bundle", "expired-bundle", "replay-bundle", "bundle-public-key", "release-public-key", "release-root", "release-online-keys", "package-public-key", "advisories"} {
		value := FlagValue(args, name)
		if value == "" {
			continue
		}
		var destination string
		switch {
		case remoteSecretFlag(name):
			destination, err = stage.secret(value)
		case strings.Contains(name, "build") || strings.Contains(name, "repository") || name == "rejections":
			destination, err = stage.record(value)
		default:
			destination, err = stage.input(value)
		}
		if err != nil {
			return fmt.Errorf("stage -%s: %w", name, err)
		}
		args = SetFlag(args, name, destination)
	}
	outputs := map[string]string{}
	for _, name := range []string{"record", "inventory-record", "diagnostics", "fixture-output", "evidence"} {
		if value := FlagValue(args, name); value != "" {
			if name != "diagnostics" {
				if _, e := os.Lstat(value); !errors.Is(e, os.ErrNotExist) {
					return fmt.Errorf("-%s destination must not exist", name)
				}
			}
			outputs[name] = value
			if name == "evidence" {
				// Created up front, exclusively, so a held run's controller can
				// place owner-only files beside the returned evidence.
				if err := os.Mkdir(value, 0o700); err != nil {
					return err
				}
			}
			args = SetFlag(args, name, remote+"/records/"+name)
			if name == "diagnostics" {
				if err := stage.mkdir(remote + "/records/diagnostics"); err != nil {
					return err
				}
			}
		}
	}
	if consoleBrowserLane(args[1]) && FlagValue(args, "browser-config") != "" {
		browserConfig, err := stage.enrollmentBrowser(FlagValue(args, "browser-config"), outputs)
		if err != nil {
			return fmt.Errorf("stage enrollment browser: %w", err)
		}
		args = SetFlag(args, "browser-config", browserConfig)
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
	if r.BatchCredential != "" {
		credentialPath := filepath.Join(local, "batch-credential")
		if err := os.WriteFile(credentialPath, []byte(r.BatchCredential), 0600); err != nil {
			return err
		}
		if err := stage.sync(credentialPath, remote+"/batch-credential"); err != nil {
			return err
		}
		argv = []string{remote + "/bin/lab", "host-exec-batch", remote + "/batch-credential", remote + "/host.json"}
	}
	argv = append(argv, args...)
	command := make([]string, len(argv))
	for i, s := range argv {
		command[i] = QuoteShell(s)
	}
	script := "cd " + QuoteShell(remote+"/source") + " && exec env " + QuoteShell("TMPDIR="+remote+"/work") + " " + strings.Join(command, " ")
	if (args[1] == "assistance" && FlagValue(args, "demo-device") == "") || (consoleBrowserLane(args[1]) && FlagValue(args, "browser-config") != "") {
		browserEnv, err := stage.assistanceBrowser(work, nativeArch)
		if err != nil {
			return err
		}
		script = browserEnv + "\n" + script
	}
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
		case "dispatch", "resources", "device-actions", "updates", "enroll-unattended", "lifecycle", "assistance", "advisories":
			database = " --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock --group-add \"$(stat -c %g /var/run/docker.sock)\""
		}
		script = "exec docker run -i --name " + QuoteShell(container) + " --network host --user \"$(id -u):$(id -g)\"" + devices + database + " --mount " + QuoteShell("type=bind,src="+work+",dst="+work) + " --workdir " + QuoteShell(remote+"/source") + " --env " + QuoteShell("TMPDIR="+remote+"/work") + " " + QuoteShell(r.Host.RunnerImage) + " " + strings.Join(command, " ")
	}
	forwards, err := reverseForwardOptions(r.ReverseForwards)
	if err != nil {
		return err
	}
	if len(forwards) != 0 && r.Host.SshAlias == "" {
		return errors.New("reverse forwards require an SSH lab host")
	}
	started := time.Now().UTC()
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	cmd := executionCommand(runCtx, r.Host.SshAlias, script, forwards...)
	// A terminal Ctrl-C belongs to the controller, not SSH. Keep SSH alive
	// while cancellation closes stdin and the worker tears down its lease.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// The open pipe is a lifetime lease. EOF on disconnect cancels the remote
	// worker, which joins VM children and fixture cleanup before releasing flock.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	// Let stdin EOF cancel the worker and finish teardown before SSH exits.
	cmd.Cancel = cancelByClosingLease(stdin)
	cmd.WaitDelay = 2 * time.Minute
	cmd.Stdout, cmd.Stderr = r.Stdout, r.Stderr
	runErr := cmd.Start()
	var heldErr error
	if runErr == nil {
		watched := make(chan struct{})
		if (r.OnHeld != nil || r.OnRegistration != nil) && outputs["evidence"] != "" {
			go func() {
				defer close(watched)
				if heldErr = r.watchHeld(runCtx, remote+"/records/evidence", 10*time.Second); heldErr != nil {
					cancelRun()
				}
			}()
		} else {
			close(watched)
		}
		runErr = cmd.Wait()
		cancelRun()
		<-watched
	}
	if r.Hold && ctx.Err() != nil && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		// The worker acknowledged EOF and completed fixture/VM teardown.
		runErr = nil
	}
	var sshExit *exec.ExitError
	if runErr != nil && (!errors.As(runErr, &sshExit) || sshExit.ExitCode() == 255 || sshExit.ExitCode() < 0) {
		preserveRemote = true
	}
	closeErr := stdin.Close()
	if errors.Is(closeErr, os.ErrClosed) {
		closeErr = nil
	}
	err = errors.Join(runErr, closeErr, heldErr)
	copyCtx, stop := context.WithTimeout(context.Background(), 5*time.Minute)
	defer stop()
	// Remote output paths embedded in the lane record (e.g. inspect's
	// InventoryRecordPath) are rewritten to their local copies; the record is
	// returned last so it never names a local file that has not been copied.
	relocated := map[string]string{}
	for _, name := range []string{"browser-credential", "approver-credential", "evidence", "inventory-record", "diagnostics", "fixture-output", "record"} {
		destination, ok := outputs[name]
		if !ok {
			continue
		}
		remotePath := remote + "/records/" + name
		if _, existsErr := runOutput(copyCtx, r.Host.SshAlias, "test -e "+QuoteShell(remotePath)); existsErr != nil {
			var exit *exec.ExitError
			missing := errors.As(existsErr, &exit) && exit.ExitCode() == 1
			if !missing {
				preserveRemote = true
				err = errors.Join(err, fmt.Errorf("check remote -%s evidence: %w", name, existsErr))
			} else if runErr == nil {
				err = errors.Join(err, fmt.Errorf("remote -%s record missing: %w", name, existsErr))
			}
			continue
		}
		if name == "evidence" {
			if e := collectAssistanceEvidence(copyCtx, r.Host.SshAlias, remotePath, destination, r.Stderr); e != nil {
				err = errors.Join(err, e)
				preserveRemote = true
			} else if absolute, e := filepath.Abs(destination); e != nil {
				err = errors.Join(err, e)
			} else {
				relocated[remotePath] = absolute
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
		if name == "browser-credential" || name == "approver-credential" {
			if e := returnEnrollmentCredential(target, destination); e != nil {
				err = errors.Join(err, e)
				preserveRemote = true
			}
			continue
		}
		if name == "record" {
			if e := annotateRemoteRecord(target, r.Host, started, time.Now().UTC(), revision, diffDigest, relocated); e != nil {
				err = errors.Join(err, e)
				preserveRemote = true
				continue
			}
		}
		if name != "diagnostics" && name != "fixture-output" {
			if e := publishRecord(target, destination); e != nil {
				err = errors.Join(err, e)
				preserveRemote = true
				continue
			}
		}
		absolute, e := filepath.Abs(destination)
		if e != nil {
			err = errors.Join(err, e)
			continue
		}
		relocated[remote+"/records/"+name] = absolute
	}
	if runErr == nil && args[1] == "snapshot" {
		destination := FlagValue(r.Args, "snapshot-cache")
		if destination == "" {
			destination = cache
		}
		// Multi-GiB authenticated closures have their own bounded lifetime,
		// not the short post-run budget for returning small evidence records.
		transferCtx, stopTransfer := context.WithTimeout(ctx, 45*time.Minute)
		transferErr := collectRepositorySnapshot(transferCtx, r.Host.SshAlias, remote+"/bin/lab", filepath.Join(work, "images"), destination, outputs["record"], r.Stderr)
		stopTransfer()
		if transferErr != nil {
			preserveRemote = true
			err = errors.Join(err, transferErr)
		}
	}
	return err
}

// collectAssistanceEvidence returns immutable records and screenshots into the
// run's exclusively created destination, but never the held owner's
// credentials or the held and registration control markers.
func collectAssistanceEvidence(ctx context.Context, alias, source, destination string, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, "rsync", "-a", "--protect-args", "--chmod=Du=rwx,Dgo=", "--exclude=/owner-access", "--exclude=/"+heldMarker, "--exclude=/"+RegistrationMarker, "-e", "ssh -o BatchMode=yes -o ConnectTimeout=10", "--", transferPath(alias, source+"/"), destination+"/")
	cmd.Stdout, cmd.Stderr = stderr, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("collect assistance evidence: %w", err)
	}
	return nil
}

// watchHeld polls the remote evidence directory until the run ends or is
// held. Every registration marker goes to OnRegistration before the held
// probe. Once the held marker is present, it reads the bounded marker without
// logging it, removes it remotely and hands it to OnHeld exactly once.
func (r RemoteRun) watchHeld(ctx context.Context, dir string, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	marker := dir + "/" + heldMarker
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		if r.OnRegistration != nil {
			if err := r.acknowledgeRegistration(ctx, dir+"/"+RegistrationMarker); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
		if r.OnHeld == nil {
			continue
		}
		probe := executionCommand(ctx, r.Host.SshAlias, "test -e "+QuoteShell(marker))
		if err := probe.Run(); err != nil {
			var exit *exec.ExitError
			if ctx.Err() != nil || (errors.As(err, &exit) && exit.ExitCode() == 1) {
				continue
			}
			return fmt.Errorf("probe held marker: %w", err)
		}
		read := executionCommand(ctx, r.Host.SshAlias, "head -c "+strconv.Itoa(maxHeldMarker+1)+" -- "+QuoteShell(marker)+" && rm -f -- "+QuoteShell(marker))
		out := baselineOutput{limit: maxHeldMarker}
		read.Stdout = &out
		err := read.Run()
		data := out.Bytes()
		defer clear(data)
		if ctx.Err() != nil {
			// The run ended while the marker was being read: nothing to hold.
			return nil
		}
		if err != nil || out.exceeded {
			return errors.New("read held marker failed or exceeded its bound")
		}
		if err := r.OnHeld(ctx, data); err != nil && ctx.Err() == nil {
			return err
		}
		// A run that ended (Ctrl-C or remote teardown) while OnHeld waited is
		// an orderly shutdown, not a held-access failure.
		return nil
	}
}

// acknowledgeRegistration hands a present registration marker to
// OnRegistration and removes it only once that returned: the worker waits for
// the removal, so it never continues before the controller's record.
func (r RemoteRun) acknowledgeRegistration(ctx context.Context, marker string) error {
	const absent = 3
	read := executionCommand(ctx, r.Host.SshAlias, "test -e "+QuoteShell(marker)+" || exit "+strconv.Itoa(absent)+"; head -c "+strconv.Itoa(maxHeldMarker+1)+" -- "+QuoteShell(marker))
	out := baselineOutput{limit: maxHeldMarker}
	read.Stdout = &out
	err := read.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == absent {
		return nil
	}
	if err != nil || out.exceeded {
		return errors.New("read registration marker failed or exceeded its bound")
	}
	if err := r.OnRegistration(ctx, out.Bytes()); err != nil {
		return fmt.Errorf("record registration: %w", err)
	}
	if err := executionCommand(ctx, r.Host.SshAlias, "rm -f -- "+QuoteShell(marker)).Run(); err != nil {
		return fmt.Errorf("acknowledge registration: %w", err)
	}
	return nil
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

// annotateRemoteRecord adds host provenance to the private returned copy. Lanes
// may finalize their remote record read-only (device-actions chmods it 0400)
// and rsync preserves that mode, so the annotated copy replaces it by rename
// rather than by writing through the read-only file.
func annotateRemoteRecord(path string, host *labv1.LabHost, start, end time.Time, revision, diffDigest string, relocated map[string]string) (err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var record map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err = decoder.Decode(&record); err != nil {
		return err
	}
	if record == nil || len(bytes.TrimSpace(data[decoder.InputOffset():])) != 0 {
		return errors.New("remote lane record must contain exactly one JSON object")
	}
	record["lab_host"] = map[string]any{"name": host.Name, "transport": host.Transport, "ssh_alias": host.SshAlias, "runtime": host.Runtime, "runner_image": host.RunnerImage, "started_at": start, "finished_at": end, "elapsed_seconds": end.Sub(start).Seconds(), "source_revision": revision, "source_diff_sha256": diffDigest}
	relocateReturnedRecord(record, relocated)
	data, err = json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	annotated, err := os.CreateTemp(filepath.Dir(path), ".annotated-")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(annotated.Name()))
		}
	}()
	_, err = annotated.Write(append(data, '\n'))
	if err == nil {
		err = annotated.Sync()
	}
	if err = errors.Join(err, annotated.Close()); err != nil {
		return err
	}
	return os.Rename(annotated.Name(), path)
}

func relocateReturnedRecord(value any, relocated map[string]string) any {
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			value[key] = relocateReturnedRecord(item, relocated)
		}
	case []any:
		for index, item := range value {
			value[index] = relocateReturnedRecord(item, relocated)
		}
	case string:
		var source, destination string
		for remote, local := range relocated {
			if len(remote) <= len(source) {
				continue
			}
			if value == remote {
				source, destination = remote, local
			} else if relative, ok := strings.CutPrefix(value, remote+"/"); ok && filepath.IsLocal(relative) {
				source, destination = remote, filepath.Join(local, relative)
			}
		}
		if source != "" {
			return destination
		}
	}
	return value
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
	// Native repositories bind package basenames as well as signed bytes. Keep
	// the name intact and isolate equal names in separate staging directories.
	target := filepath.Join(s.remote, "inputs", strconv.Itoa(len(s.copied)), filepath.Base(absolute))
	if err := s.mkdir(filepath.Dir(target)); err != nil {
		return "", err
	}
	source := absolute
	if info.IsDir() {
		source += "/"
	}
	if err := s.sync(source, target); err != nil {
		return "", err
	}
	s.copied[absolute] = target
	return target, nil
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
				if key == "packages" {
					indexes, ok := item.(map[string]any)
					if !ok {
						return errors.New("APT packages record must name architecture-specific indexes")
					}
					for architecture, index := range indexes {
						path, ok := index.(string)
						if !ok || path == "" {
							return errors.New("APT architecture index path is missing")
						}
						target, e := s.input(path)
						if e != nil {
							return e
						}
						indexes[architecture] = target
					}
					continue
				}
				text, ok := item.(string)
				if ok && text != "" && (key == "path" || key == "public_key" || key == "public_key_armor" || key == "signature_path" || key == "binary" || key == "inrelease" || key == "release" || key == "database" || key == "database_signature" || key == "repomd") {
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
