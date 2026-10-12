package labhost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
)

func remoteDestroyRequested(args []string) bool {
	for _, arg := range args {
		name, value, explicit := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if strings.HasPrefix(arg, "-") && name == "destroy" {
			parsed, err := strconv.ParseBool(value)
			return !explicit || err == nil && parsed
		}
	}
	return false
}

// destroyAssistance uses the current native lab binary and normal host-exec
// admission. Only that maintained command validates and removes persistent state;
// transport cleanup owns just its new staging directory, never the demo root.
func (r RemoteRun) destroyAssistance(ctx context.Context) (err error) {
	if r.Host.Transport != "ssh" || r.Host.Runtime != "native" {
		return errors.New("persistent remote assistance requires SSH-native host")
	}
	work := r.Host.WorkDirectory
	if strings.HasPrefix(work, "~/") {
		home, err := runOutput(ctx, r.Host.SshAlias, `printf '%s' "$HOME"`)
		if err != nil {
			return err
		}
		work = filepath.Join(home, strings.TrimPrefix(work, "~/"))
	}
	name := FlagValue(r.Args, "name")
	demo, err := DemoDirectory(work, name)
	if err != nil {
		return err
	}
	local, err := os.MkdirTemp("", "lindm-demo-destroy-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(local)) }()
	binary := filepath.Join(local, "lab")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binary, "./cmd/lab")
	build.Dir = r.Repository
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+r.Host.Architectures[0])
	build.Stdout, build.Stderr = r.Stderr, r.Stderr
	if err := build.Run(); err != nil {
		return err
	}
	remote, err := runOutput(ctx, r.Host.SshAlias, "umask 077; mkdir -p -- "+QuoteShell(filepath.Join(work, "runs"))+" && mktemp -d "+QuoteShell(filepath.Join(work, "runs", "run-XXXXXXXXXX")))
	if err != nil {
		return err
	}
	if filepath.Dir(remote) != filepath.Join(work, "runs") || !strings.HasPrefix(filepath.Base(remote), "run-") {
		return errors.New("unexpected remote staging directory")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, cleanErr := runOutput(cleanup, r.Host.SshAlias, "rm -rf -- "+QuoteShell(remote))
		err = errors.Join(err, cleanErr)
	}()
	stage := &remoteStage{ctx: ctx, alias: r.Host.SshAlias, local: local, remote: remote, stderr: r.Stderr, copied: make(map[string]string)}
	if err := stage.sync(binary, remote+"/lab"); err != nil {
		return err
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
	argv := []string{remote + "/lab", "host-exec", remote + "/host.json", "vm", "assistance", "-hold", "-name", name, "-destroy", "-demo-root", demo, "-work-dir", work}
	if parent := FlagValue(r.Args, "demo-parent"); parent != "" {
		argv = append(argv, "-demo-parent", parent)
	}
	// An organization device's recorded RHSM consumer is removed before its VM.
	if token := FlagValue(r.Args, "redhat-token-file"); token != "" {
		staged, err := stage.input(token)
		if err != nil {
			return fmt.Errorf("stage -redhat-token-file: %w", err)
		}
		argv = append(argv, "-redhat-token-file", staged)
	}
	for i := range argv {
		argv[i] = QuoteShell(argv[i])
	}
	command := executionCommand(ctx, r.Host.SshAlias, "exec "+strings.Join(argv, " "))
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := command.StdinPipe()
	if err != nil {
		return err
	}
	command.Cancel, command.WaitDelay = stdin.Close, 2*time.Minute
	command.Stdout, command.Stderr = r.Stdout, r.Stderr
	runErr := command.Run()
	closeErr := stdin.Close()
	if errors.Is(closeErr, os.ErrClosed) {
		closeErr = nil
	}
	return errors.Join(runErr, closeErr)
}
