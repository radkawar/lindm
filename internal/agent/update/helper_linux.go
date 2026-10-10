package update

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/statefs"
)

const recoveryUnit = "lindm-agent-update-recovery.service"
const unitDirectory = "/etc/systemd/system"

func helperUnit(tx *agentv1.AgentUpdateTransaction) string {
	return "lindm-agent-update-" + tx.GetId() + ".service"
}

func preserveHelper(directory string) (resultErr error) {
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, source.Close()) }()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<20 {
		return errors.New("recovery executable exceeds bound")
	}
	out, err := os.OpenFile(filepath.Join(directory, "helper"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(out, io.LimitReader(source, (256<<20)+1))
	if copyErr != nil || n != info.Size() {
		return errors.Join(errors.New("copy recovery executable failed"), copyErr, out.Close())
	}
	// Preserve only the executable's actual SELinux context. Never disable MAC,
	// relabel a whole directory, or trust a network-supplied label.
	label := make([]byte, 4096)
	size, err := unix.Fgetxattr(int(source.Fd()), "security.selinux", label)
	if err == nil {
		if err := unix.Fsetxattr(int(out.Fd()), "security.selinux", label[:size], 0); err != nil {
			return errors.Join(err, out.Close())
		}
	} else if !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		return errors.Join(err, out.Close())
	}
	if err := out.Sync(); err != nil {
		return errors.Join(err, out.Close())
	}
	if err := out.Close(); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func launchHelper(ctx context.Context, directory string, tx *agentv1.AgentUpdateTransaction) error {
	// No dependency on lindm-executor/agent services: package scripts can replace
	// or stop them without killing this independently owned cgroup. systemd's
	// PrivateNetwork and AF_UNIX fence also cover native package manager scripts.
	_, err := nativeCommand(ctx, "apply", "/usr/bin/systemd-run", "--quiet", "--no-block", "--collect", "--unit="+helperUnit(tx), "--property=Slice=lindm-updates.slice", "--property=Type=exec", "--property=PrivateNetwork=yes", "--property=RestrictAddressFamilies=AF_UNIX", "--property=RuntimeMaxSec=1800", "--property=UMask=0077", "--property=StandardOutput=journal", "--property=StandardError=journal", filepath.Join(directory, "helper"), "update-apply", "-transaction", directory)
	return err
}

func helperActive(ctx context.Context, tx *agentv1.AgentUpdateTransaction) (bool, error) {
	for _, unit := range []string{helperUnit(tx), recoveryUnit} {
		out, err := nativeCommand(ctx, "recovery", "/usr/bin/systemctl", "show", "--property=LoadState,ActiveState,SubState", unit)
		fields := make(map[string]string)
		for line := range strings.SplitSeq(string(out), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				fields[k] = v
			}
		}
		if fields["LoadState"] == "not-found" {
			continue
		}
		if err != nil {
			return false, err
		}
		if fields["ActiveState"] == "activating" || fields["SubState"] == "running" || fields["SubState"] == "start" {
			return true, nil
		}
	}
	return false, nil
}

// Apply runs only from the protected copied executable in an independently owned
// systemd unit. It retains a boot-persistent recovery unit until actual native
// installed/configured state and payload match the immutable transaction.
func Apply(ctx context.Context, directory string) (resultErr error) {
	if os.Geteuid() != 0 {
		return errors.New("update helper requires root")
	}
	ownNetwork, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return err
	}
	hostNetwork, err := os.Stat("/proc/1/ns/net")
	if err != nil {
		return err
	}
	if os.SameFile(ownNetwork, hostNetwork) {
		return errors.New("update helper requires systemd PrivateNetwork isolation")
	}
	fd, err := statefs.OpenDirectory(directory)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(fd)) }()
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("native update transaction already owned")
	}
	tx := &agentv1.AgentUpdateTransaction{}
	if err := journal.ReadUpdateRecord(directory, "transaction.pb", tx); err != nil {
		return err
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(tx, &agentv1.AgentUpdateHelperState{}), protovalidate.WithDisableLazy())
	if err != nil {
		return err
	}
	if err := validator.Validate(tx); err != nil {
		return err
	}
	if filepath.Base(directory) != tx.GetId() {
		return errors.New("native update transaction directory mismatch")
	}
	previous := &agentv1.AgentUpdateHelperState{}
	readErr := journal.ReadUpdateRecord(directory, "helper.pb", previous)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if readErr == nil {
		if err := validator.Validate(previous); err != nil {
			return err
		}
	}
	completed := false
	operation := "validation"
	defer func() {
		if resultErr == nil || completed {
			return
		}
		phase := "recovery_required"
		if errors.Is(resultErr, errTransactionExpired) {
			phase = "rejected"
			resultErr = errors.Join(resultErr, removeRecoveryUnit(ctx, directory))
		}
		resultErr = withNativeDiagnostic(resultErr, managerExecutable(tx.GetManager()), operation)
		resultErr = errors.Join(resultErr, writeHelperState(directory, phase, previous, resultErr))
	}()
	if err := mutablePlatform(tx.GetManager()); err != nil {
		return err
	}
	if err := validatePackage(ctx, directory, tx); err != nil {
		return err
	}
	operation = "recovery"
	prior, err := observeInstalled(ctx, tx.GetManager(), operation)
	if err != nil {
		return err
	}
	if !recoverablePredecessor(prior, tx, previous.GetPhase()) {
		return errors.New("native package changed outside admitted transaction")
	}
	if previous.GetPhase() == "installed" && prior.matchesTransaction(tx) == nil {
		if err := verifyInstalledPayload(ctx, tx); err != nil {
			return err
		}
		if err := writeHelperState(directory, "installed", previous, nil); err != nil {
			return err
		}
		completed = true
		return removeRecoveryUnit(ctx, directory)
	}
	if err := authorizeNativeEffect(ctx, tx, prior, previous.GetPhase()); err != nil {
		return err
	}
	// Install the reboot path and sync it BEFORE recording/installing any native
	// effect. A power loss can lose neither both current executable and recovery.
	if err := installRecoveryUnit(ctx, directory); err != nil {
		return err
	}
	if err := writeHelperState(directory, "installing", previous, nil); err != nil {
		return err
	}
	if err := applyPackage(ctx, directory, tx, prior, readErr == nil, func() error {
		return authorizeNativeEffect(ctx, tx, prior, previous.GetPhase())
	}); err != nil {
		return err
	}
	installed, err := observeInstalled(ctx, tx.GetManager(), "payload_verify")
	if err != nil {
		return err
	}
	if err := installed.matchesTransaction(tx); err != nil {
		return withNativeDiagnostic(err, managerExecutable(tx.GetManager()), "payload_verify")
	}
	if err := verifyInstalledPayload(ctx, tx); err != nil {
		return err
	}
	if err := writeHelperState(directory, "installed", previous, nil); err != nil {
		return err
	}
	completed = true
	return removeRecoveryUnit(ctx, directory)
}

// Keep the last failure while a rebooted helper is checking/recovering. Only a
// verified installed checkpoint clears it; a missing new diagnostic is not success.
func writeHelperState(directory, phase string, previous *agentv1.AgentUpdateHelperState, failure error) error {
	diagnostic := previous.GetNativeDiagnostic()
	if next := diagnosticForError(failure); next != nil {
		diagnostic = next
	}
	if phase == "installed" {
		diagnostic = nil
	}
	return journal.WriteUpdateRecord(directory, "helper.pb", &agentv1.AgentUpdateHelperState{Phase: phase, ObservedAt: timestamppb.Now(), NativeDiagnostic: diagnostic})
}

func recoveryUnitBytes(directory string) []byte {
	quote := func(s string) string { return strconv.Quote(strings.ReplaceAll(s, "%", "%%")) }
	// Type=exec releases ordering after the protected binary starts, not after
	// its package transaction finishes: native postinst may synchronously restart
	// the executor without waiting on this same helper and deadlocking.
	return []byte("# Owned by lindm-agent verified update recovery.\n[Unit]\nDescription=Lindm agent interrupted native update recovery\nAfter=local-fs.target\nBefore=lindm-executor.service lindm-agent.service\n[Service]\nType=exec\nSlice=lindm-updates.slice\nExecStart=" + quote(filepath.Join(directory, "helper")) + " update-apply -transaction " + quote(directory) + "\nPrivateNetwork=yes\nRestrictAddressFamilies=AF_UNIX\nUMask=0077\nRuntimeMaxSec=1800\nStandardOutput=journal\nStandardError=journal\n[Install]\nWantedBy=multi-user.target\n")
}

func installRecoveryUnit(ctx context.Context, directory string) error {
	fd, err := statefs.OpenTemporaryParent(unitDirectory)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	path := filepath.Join(unitDirectory, recoveryUnit)
	expected := recoveryUnitBytes(directory)
	if existing, err := readOwnedUnit(path); err == nil {
		if string(existing) != string(expected) {
			return errors.New("recovery unit belongs to another transaction")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		file, err := os.CreateTemp(unitDirectory, ".lindm-update-unit-")
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(file.Name()) }()
		if err := file.Chmod(0644); err != nil {
			return errors.Join(err, file.Close())
		}
		if _, err := file.Write(expected); err != nil {
			return errors.Join(err, file.Close())
		}
		if err := file.Sync(); err != nil {
			return errors.Join(err, file.Close())
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Rename(file.Name(), path); err != nil {
			return err
		}
	} else {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	wants := filepath.Join(unitDirectory, "multi-user.target.wants")
	if err := os.Mkdir(wants, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	wantsFD, err := statefs.OpenTemporaryParent(wants)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(wantsFD) }()
	link := filepath.Join(wants, recoveryUnit)
	if err := os.Symlink("../"+recoveryUnit, link); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		target, err := os.Readlink(link)
		if err != nil || target != "../"+recoveryUnit {
			return errors.New("recovery boot link is not owned")
		}
	}
	if err := unix.Fsync(wantsFD); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	_, err = nativeCommand(ctx, "recovery", "/usr/bin/systemctl", "daemon-reload")
	return err
}

func readOwnedUnit(path string) (data []byte, resultErr error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "update-recovery-unit")
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Uid != 0 || stat.Nlink != 1 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0022 != 0 || stat.Size > 8192 {
		return nil, errors.New("unowned update recovery unit")
	}
	return io.ReadAll(io.LimitReader(file, 8193))
}

func removeRecoveryUnit(ctx context.Context, directory string) error {
	path := filepath.Join(unitDirectory, recoveryUnit)
	existing, err := readOwnedUnit(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(existing) != string(recoveryUnitBytes(directory)) {
		return errors.New("refuse removing unowned update recovery unit")
	}
	wants := filepath.Join(unitDirectory, "multi-user.target.wants")
	link := filepath.Join(wants, recoveryUnit)
	target, err := os.Readlink(link)
	if err == nil {
		if target != "../"+recoveryUnit {
			return errors.New("refuse removing unowned recovery link")
		}
		if err := os.Remove(link); err != nil {
			return err
		}
		if err := syncDirectory(wants); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if err := syncDirectory(unitDirectory); err != nil {
		return err
	}
	_, err = nativeCommand(ctx, "recovery", "/usr/bin/systemctl", "daemon-reload")
	return err
}

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}
