//go:build linux

package osupdate

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/resource"
)

// The marker survives reboot independently of the replaceable deferral ledger.
// Its presence is an uncertain native package outcome, never permission to retry
// or automatically roll back a root filesystem and its execution-authority state.
const rollingHoldPath = resource.OSUpdateRunStatePath + ".rolling-in-progress"
const rollingRootHoldPath = "/etc/lindm/os-update/rolling-in-progress.binpb"

func rollingHold() error {
	return rollingHoldFiles([]string{rollingHoldPath, rollingRootHoldPath}, 0)
}

func rollingHoldFiles(paths []string, owner uint32) error {
	for _, path := range paths {
		_, err := readOwned(path, statusLimit, owner)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		return &nativeFailure{reason: "rolling_recovery_hold", diagnostic: runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_VALIDATION, "interrupted whole-system transaction requires native recovery; automatic retry and rollback refused")}
	}
	return nil
}

func (r *Runner) beginRollingHold(summary *agentv1.PatchRunSummary) error {
	receipt := proto.CloneOf(summary)
	receipt.Result = agentv1.PatchRunResult_PATCH_RUN_RESULT_FAILED
	receipt.Diagnostic = runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, "whole-system transaction outcome not yet known")
	receipt.FinishedAt = timestamppb.New(r.now())
	data, err := r.marshalValidated(receipt)
	if err != nil {
		return err
	}
	if err := writeAtomic(rollingHoldPath, data); err != nil {
		return err
	}
	return writeAtomic(rollingRootHoldPath, data)
}

func clearRollingHold() error {
	for _, path := range []string{rollingHoldPath, rollingRootHoldPath} {
		if err := clearRollingMarker(path); err != nil {
			return err
		}
	}
	return nil
}

func clearRollingMarker(path string) error {
	if err := unix.Unlink(path); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	fd, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	return errors.Join(unix.Fsync(fd), unix.Close(fd))
}

// verifySnapshotReplayMarker establishes the actual nonrecursive-snapshot
// postcondition, not an inference from filesystem or mount identity.
func verifySnapshotReplayMarker(current, saved string, owner uint32) error {
	before, err := readSnapshotMarker(current, owner)
	if err != nil {
		return err
	}
	snapshot, err := readSnapshotMarker(saved, owner)
	if err != nil {
		return err
	}
	if len(before) == 0 || !bytes.Equal(before, snapshot) {
		return errors.New("snapper_replay_marker_not_retained")
	}
	return nil
}

// No component may be a symlink to the live tree. A final-only O_NOFOLLOW
// check would accept snapshot/etc -> /etc and invent a saved replay guard.
func readSnapshotMarker(path string, owner uint32) (data []byte, err error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { err = errors.Join(err, file.Close()) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != owner || st.Mode&0022 != 0 {
		return nil, errFileUnsafe
	}
	data, err = io.ReadAll(io.LimitReader(file, statusLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > statusLimit {
		return nil, errFileSize
	}
	return data, nil
}
