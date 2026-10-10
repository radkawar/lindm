//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/localrpc"
	"lindm/internal/packaging"
)

// guestUpdateUnpack freezes only the admitted native helper, after observing an
// actual partial executable write. The host resets its owned QEMU guest after the
// witness returns. It must never retry this mutating probe on transport loss.
func guestUpdateUnpack(ctx context.Context, output io.Writer) (resultErr error) {
	if os.Geteuid() != 0 {
		return errors.New("native unpack fault observation requires root")
	}
	doc, err := config.Load(config.ExecutorConfigPath)
	if err != nil {
		return errors.New("cannot load protected executor configuration")
	}
	client, cleanup, err := localrpc.Dial(doc.SocketPath)
	if err != nil {
		return errors.New("cannot dial root executor")
	}
	defer func() { resultErr = errors.Join(resultErr, cleanup()) }()
	watch, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(watch)) }()
	if _, err := unix.InotifyAddWatch(watch, filepath.Dir(packaging.BinaryPath), unix.IN_CREATE|unix.IN_MODIFY|unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO); err != nil {
		return err
	}
	var group string
	var nextStatus time.Time
	buffer := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(nextStatus) {
			call, cancel := context.WithTimeout(ctx, 5*time.Second)
			response, statusErr := client.GetAgentUpdate(call, connect.NewRequest(&agentv1.GetAgentUpdateRequest{}))
			cancel()
			nextStatus = time.Now().Add(time.Second)
			if statusErr != nil && connect.CodeOf(statusErr) != connect.CodeUnavailable {
				return errors.New("protected native update status unavailable")
			}
			if statusErr == nil {
				status := response.Msg.GetStatus()
				if terminal := guestUpdateUnpackTerminal(status); terminal != nil {
					return fmt.Errorf("%w (observed helper cgroup %q)", terminal, group)
				}
				if status.GetTransactionId() != "" {
					id, err := uuid.Parse(status.GetTransactionId())
					if err != nil || id == uuid.Nil || id.String() != status.GetTransactionId() {
						return errors.New("invalid protected native transaction identity")
					}
					unit := "lindm-agent-update-" + id.String() + ".service"
					if group == "" {
						group, err = nativeUpdateCgroup(ctx, unit)
						if err != nil {
							return err
						}
					}
				}
			}
		}
		if group != "" {
			witness, err := freezeNativeUnpack(ctx, group, packaging.BinaryPath)
			if err != nil {
				return err
			}
			if witness != "" {
				_, err := fmt.Fprintln(output, witness)
				return err
			}
		}
		poll := []unix.PollFd{{Fd: int32(watch), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, 100); err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if poll[0].Revents&unix.POLLIN != 0 {
			if _, err := unix.Read(watch, buffer); err != nil && !errors.Is(err, unix.EAGAIN) {
				return err
			}
		}
	}
}

func nativeUpdateCgroup(ctx context.Context, unit string) (string, error) {
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(call, "/usr/bin/systemctl", "show", "--property=LoadState", "--property=ControlGroup", "--", unit)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	data, err := command.Output()
	group, parseErr := parseNativeUpdateCgroup(unit, data)
	if parseErr != nil {
		return "", parseErr
	}
	if strings.Contains("\n"+string(data), "\nLoadState=not-found\n") {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve admitted native helper cgroup: %w", err)
	}
	return group, nil
}

func parseNativeUpdateCgroup(unit string, data []byte) (string, error) {
	if len(data) > 16<<10 {
		return "", errors.New("native helper unit observation exceeds bound")
	}
	var group string
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "ControlGroup="); ok {
			group = value
		}
	}
	if group == "" {
		return "", nil // The admitted transient unit may not have launched yet.
	}
	if !filepath.IsAbs(group) || filepath.Clean(group) != group || filepath.Base(group) != unit {
		return "", errors.New("native helper cgroup does not match admitted unit")
	}
	return "/sys/fs/cgroup" + group, nil
}

func nativeUnpackFiles(binary string) ([]string, error) {
	files, err := filepath.Glob(binary + ";*")
	return append(files, binary+".dpkg-new"), err
}

func partialNativeFile(path string) (int64, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("native unpack witness is not a regular file")
	}
	return info.Size(), nil
}

func freezeNativeUnpack(ctx context.Context, group, binary string) (witness string, resultErr error) {
	files, err := nativeUnpackFiles(binary)
	if err != nil {
		return "", err
	}
	for _, file := range files {
		size, err := partialNativeFile(file)
		if err != nil {
			return "", err
		}
		if size == 0 {
			continue
		}
		freeze, err := os.OpenFile(filepath.Join(group, "cgroup.freeze"), os.O_WRONLY, 0)
		if err != nil {
			return "", err
		}
		// Keep the same kernel cgroup handle for thaw on every unsuccessful
		// observation. Successful witnesses deliberately leave the helper frozen.
		defer func() {
			if witness == "" || resultErr != nil {
				_, thawErr := freeze.WriteAt([]byte("0"), 0)
				resultErr = errors.Join(resultErr, thawErr)
			}
			resultErr = errors.Join(resultErr, freeze.Close())
		}()
		if _, err := freeze.Write([]byte("1")); err != nil {
			return "", err
		}
		frozen, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			events, err := readUpdateKernelFile(filepath.Join(group, "cgroup.events"))
			if err != nil {
				return "", err
			}
			if strings.Contains("\n"+string(events), "\nfrozen 1\n") {
				break
			}
			select {
			case <-frozen.Done():
				return "", fmt.Errorf("native helper cgroup did not freeze: %w", frozen.Err())
			case <-tick.C:
			}
		}
		// Re-observe only after the kernel reports all cgroup tasks frozen.
		// A rename which won the race is not interruption evidence.
		size, err = partialNativeFile(file)
		if err != nil || size == 0 {
			return "", err
		}
		processes, err := readUpdateKernelFile(filepath.Join(group, "cgroup.procs"))
		if err != nil {
			return "", err
		}
		var observed []string
		for _, raw := range strings.Fields(string(processes)) {
			pid, err := strconv.Atoi(raw)
			if err != nil || pid <= 0 {
				return "", errors.New("invalid native helper cgroup process")
			}
			comm, err := readUpdateKernelFile(filepath.Join("/proc", raw, "comm"))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return "", err
			}
			name := strings.TrimSpace(string(comm))
			observed = append(observed, fmt.Sprintf("%d:%q", pid, name))
			if name == "dnf" || name == "dnf5" || name == "dpkg" || name == "apt-get" {
				return fmt.Sprintf("%s pid=%d unpack=%s bytes=%d cgroup=%s frozen=1", name, pid, file, size, filepath.Base(group)), nil
			}
		}
		return "", fmt.Errorf("partial native file %s (%d bytes) has no native manager in frozen cgroup %s: %s", file, size, group, strings.Join(observed, ","))
	}
	return "", nil
}

func guestUpdateUnpackTerminal(status *agentv1.AgentUpdateStatus) error {
	switch status.GetPhase() {
	case "recovery_required", "rejected", "installed":
		data, err := protojson.Marshal(status)
		return errors.Join(fmt.Errorf("native update terminal before frozen unpack witness: %s", data), err)
	default:
		return nil
	}
}

func readUpdateKernelFile(path string) (data []byte, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	data, err = io.ReadAll(io.LimitReader(file, (16<<10)+1))
	if len(data) > 16<<10 {
		return nil, errors.New("native update kernel observation exceeds bound")
	}
	return data, err
}
