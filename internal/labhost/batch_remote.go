package labhost

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
)

// BatchRequest starts the executing host's reservation broker. The controller
// must acquire hosts in a global order, then keep each reservation until every
// worker on every host has finished teardown.
type BatchRequest struct {
	Host       *labv1.LabHost
	Guests     uint32
	Repository string
	LabBinary  string
	Stderr     io.Writer
}

// BatchReservation owns a broker process, not a capacity bypass. Workers receive
// its credential privately and prove admission by receiving a held descriptor.
type BatchReservation struct {
	credential string
	stdin      io.WriteCloser
	done       chan struct{}
	waitErr    error
	cleanup    func() error
	once       sync.Once
	closeErr   error
}

// Credential returns a secret handoff; never put it in argv, logs or evidence.
func (b *BatchReservation) Credential() string { return b.credential }

// Wait completes when the host broker ends, including an unexpected disconnect.
func (b *BatchReservation) Wait() error {
	<-b.done
	return b.waitErr
}

// Close closes the controller lifetime pipe and waits for the host broker before
// removing only its transient staging. Workers retain inherited flock ownership.
func (b *BatchReservation) Close() error {
	b.once.Do(func() {
		closeErr := b.stdin.Close()
		if errors.Is(closeErr, os.ErrClosed) {
			closeErr = nil
		}
		waitErr := b.Wait()
		if errors.Is(waitErr, context.Canceled) {
			waitErr = nil
		}
		b.closeErr = errors.Join(closeErr, waitErr, b.cleanup())
	})
	return b.closeErr
}

// Acquire queues the whole request on the selected execution host and returns
// only after every slot is reserved. No device worker has started at this point.
func (r BatchRequest) Acquire(ctx context.Context) (_ *BatchReservation, err error) {
	if r.Host == nil || r.Host.GetRuntime() != "native" || r.Guests == 0 || r.Guests > r.Host.GetMaxGuests() {
		return nil, errors.New("lab hosts: batch requires a native host and a footprint within its capacity")
	}
	cfg := &labv1.LabConfig{Hosts: []*labv1.LabHost{r.Host}}
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	local, err := os.MkdirTemp("", "lindm-batch-stage-")
	if err != nil {
		return nil, err
	}
	cleanup := func() error { return os.RemoveAll(local) }
	cleanupOnError := true
	defer func() {
		if err != nil && cleanupOnError {
			err = errors.Join(err, cleanup())
		}
	}()
	config, err := protojson.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(local, "host.json")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		return nil, err
	}
	binary, err := filepath.Abs(r.LabBinary)
	if err != nil {
		return nil, err
	}
	alias := ""
	if r.Host.GetTransport() == "ssh" {
		alias = r.Host.GetSshAlias()
		var remoteCleanup func() error
		binary, configPath, remoteCleanup, err = r.stageBatch(ctx, local, configPath)
		if err != nil {
			return nil, err
		}
		cleanup = func() error { return errors.Join(remoteCleanup(), os.RemoveAll(local)) }
	} else if r.Host.GetTransport() != "local" {
		return nil, errors.New("lab hosts: unsupported batch transport")
	}
	argv := []string{binary, "host-batch", configPath, strconv.FormatUint(uint64(r.Guests), 10)}
	for i := range argv {
		argv[i] = QuoteShell(argv[i])
	}
	command := executionCommand(ctx, alias, "exec "+strings.Join(argv, " "))
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, errors.Join(err, stdin.Close())
	}
	command.Stderr = r.Stderr
	command.Cancel, command.WaitDelay = cancelByClosingLease(stdin), 2*time.Minute
	if err := command.Start(); err != nil {
		return nil, errors.Join(err, stdin.Close(), output.Close())
	}
	reservation := &BatchReservation{stdin: stdin, done: make(chan struct{}), cleanup: cleanup}
	go func() {
		reservation.waitErr = command.Wait()
		close(reservation.done)
	}()
	cleanupOnError = false
	credential, readErr := bufio.NewReader(io.LimitReader(output, 4096)).ReadString('\n')
	if readErr != nil {
		closeErr := reservation.Close()
		// Cancelling closes the queued broker's stdin, so its output ends with
		// EOF. That is the caller's stop, not an admission failure.
		if ctx.Err() != nil && closeErr == nil {
			return nil, context.Cause(ctx)
		}
		return nil, errors.Join(fmt.Errorf("lab hosts: read batch admission: %w", readErr), closeErr)
	}
	reservation.credential = strings.TrimSuffix(credential, "\n")
	return reservation, nil
}

func (r BatchRequest) stageBatch(ctx context.Context, local, configPath string) (binary, config string, cleanup func() error, err error) {
	binary = filepath.Join(local, "lab")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binary, "./cmd/lab")
	build.Dir = r.Repository
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+r.Host.GetArchitectures()[0])
	build.Stdout, build.Stderr = r.Stderr, r.Stderr
	if err := build.Run(); err != nil {
		return "", "", nil, err
	}
	remote, err := runOutput(ctx, r.Host.GetSshAlias(), "umask 077; mktemp -d /tmp/lindm-batch-stage-XXXXXXXXXX")
	if err != nil {
		return "", "", nil, err
	}
	if filepath.Dir(remote) != "/tmp" || !strings.HasPrefix(filepath.Base(remote), "lindm-batch-stage-") {
		return "", "", nil, errors.New("lab hosts: unexpected batch staging directory")
	}
	cleanup = func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, err := runOutput(ctx, r.Host.GetSshAlias(), "rm -rf -- "+QuoteShell(remote))
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, cleanup())
		}
	}()
	stage := &remoteStage{ctx: ctx, alias: r.Host.GetSshAlias(), local: local, remote: remote, stderr: r.Stderr}
	if err := stage.sync(binary, remote+"/lab"); err != nil {
		return "", "", cleanup, err
	}
	if err := stage.sync(configPath, remote+"/host.json"); err != nil {
		return "", "", cleanup, err
	}
	return remote + "/lab", remote + "/host.json", cleanup, nil
}
