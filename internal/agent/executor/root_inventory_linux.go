//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"
	"unicode"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const (
	rootInventoryOutputLimit     = 80 << 10
	rootInventoryDiagnosticLimit = 8 << 10
	rootInventoryCleanupTimeout  = time.Second
	rootInventoryHelper          = "/usr/libexec/lindm/lindm-agent"
)

// rootInventoryUnits runs one fixed transient unit on a connection owned by a
// single observation. run returns the unit's bounded stdout only after its main
// process exited successfully; stop joins the unit's stop job.
type rootInventoryUnits interface {
	run(ctx context.Context, properties []systemdProperty) ([]byte, error)
	stop(ctx context.Context) error
	close() error
}

// observeRootInventory starts a new host-device observation for every request.
// The executor itself keeps PrivateDevices: only this short-lived, read-only
// unit sees host block devices. Neither configuration nor caller arguments cross
// the boundary. PID 1 receives the unit and its output pipes directly on its
// private socket: no shell, systemd-run frontend or bus broker is involved.
func (s *Service) observeRootInventory(ctx context.Context) (_ *inventoryv1.RootObservation, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, &rootInventoryError{stage: "canceled", err: err}
	}
	boot, err := s.bootID()
	if _, parseErr := uuid.Parse(boot); err != nil || parseErr != nil {
		return nil, &rootInventoryError{stage: "boot_id", err: errors.Join(errInternal, err, parseErr)}
	}
	id, err := newID()
	if err != nil {
		return nil, &rootInventoryError{stage: "unit_id", err: err}
	}
	unit := "lindm-inventory-" + id + ".service"
	open := s.rootInventorySystemd
	if open == nil {
		open = openSystemdPrivateUnit
	}
	// Reserve cleanup and pipe-join time within the RPC's 15-second budget.
	// Early caller cancellation still joins bounded cleanup independently.
	deadline := time.Now().Add(12 * time.Second)
	if outer, ok := ctx.Deadline(); ok && outer.Add(-2*time.Second).Before(deadline) {
		deadline = outer.Add(-2 * time.Second)
	}
	if !deadline.After(time.Now()) {
		return nil, &rootInventoryError{stage: "deadline", err: context.DeadlineExceeded}
	}
	call, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	units, err := open(call, unit)
	if err != nil {
		// Nothing was submitted to PID 1 without an authenticated connection.
		return nil, &rootInventoryError{stage: "connect", unit: unit, err: errors.Join(errInternal, err)}
	}
	defer func() {
		if err := units.close(); err != nil && resultErr == nil {
			resultErr = &rootInventoryError{stage: "close", unit: unit, err: errors.Join(errInternal, err)}
		}
	}()
	started := s.now()
	payload, runErr := units.run(call, rootInventoryProperties())
	if runErr != nil || call.Err() != nil {
		// Even a failed/timed-out start may already have reached PID 1. Joining
		// the stop job waits for the cgroup to stop; RuntimeMaxSec is an
		// independent backstop if PID 1 cannot be reached. Never return first.
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), rootInventoryCleanupTimeout)
		stopErr := units.stop(cleanup)
		stop()
		return nil, &rootInventoryError{stage: "run", unit: unit, err: errors.Join(errInternal, runErr, call.Err()), cleanup: stopErr}
	}
	if len(payload) == 0 || len(payload) > rootInventoryOutputLimit {
		return nil, &rootInventoryError{stage: "output_bound", unit: unit, err: errInternal, payloadBytes: len(payload)}
	}
	root := new(inventoryv1.RootObservation)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, root); err != nil {
		// Decoder messages may quote payload tokens; record only the size.
		return nil, &rootInventoryError{stage: "decode", unit: unit, err: errInternal, payloadBytes: len(payload)}
	}
	if err := s.admit(root); err != nil {
		return nil, &rootInventoryError{stage: "admit", unit: unit, err: err, violations: s.violationPaths(root)}
	}
	currentBoot, err := s.bootID()
	if err != nil || currentBoot != boot || root.GetBootId() != boot || ctx.Err() != nil ||
		root.GetStartedAt().AsTime().Before(started) || root.GetFinishedAt().AsTime().After(s.now()) {
		return nil, &rootInventoryError{stage: "boot_fence", unit: unit, err: errors.Join(errInternal, err, ctx.Err())}
	}
	return root, nil
}

// rootInventoryProperties is the complete fixed sandbox of the helper unit.
// Output descriptors are appended by the launcher that owns the pipes.
func rootInventoryProperties() []systemdProperty {
	property := newSystemdProperty
	return []systemdProperty{
		property("Description", "Lindm root inventory observation"),
		property("Type", "exec"), property("User", "root"), property("Group", "root"),
		property("ExecStart", []systemdExec{{Path: rootInventoryHelper, Arguments: []string{rootInventoryHelper, "inventory-observe"}}}),
		property("PrivateDevices", false), property("DevicePolicy", "closed"),
		property("DeviceAllow", []struct{ Path, Access string }{{"block-*", "r"}}),
		property("CapabilityBoundingSet", uint64(0)), property("AmbientCapabilities", uint64(0)),
		property("NoNewPrivileges", true), property("ProtectSystem", "strict"), property("ProtectHome", "yes"),
		property("PrivateTmp", true), property("PrivateNetwork", true),
		property("RestrictAddressFamilies", systemdList{AllowList: true, Values: []string{"AF_UNIX"}}),
		property("ProtectKernelTunables", true), property("ProtectKernelModules", true), property("ProtectKernelLogs", true),
		property("ProtectClock", true), property("ProtectHostname", true), property("ProtectProc", "invisible"),
		property("ProtectControlGroups", true), property("RestrictNamespaces", uint64(0)), property("RestrictRealtime", true),
		property("RestrictSUIDSGID", true), property("LockPersonality", true), property("MemoryDenyWriteExecute", true),
		property("SystemCallArchitectures", []string{"native"}),
		property("SystemCallFilter", systemdList{AllowList: true, Values: []string{"@system-service"}}),
		property("InaccessiblePaths", []string{"-/etc/lindm", "-/var/lib/lindm", "-/run/lindm"}),
		property("UMask", uint32(0o077)), property("WorkingDirectory", "/"),
		property("RuntimeMaxUSec", uint64(10*time.Second/time.Microsecond)),
		property("TimeoutStartUSec", uint64(10*time.Second/time.Microsecond)),
		property("TimeoutStopUSec", uint64(500*time.Millisecond/time.Microsecond)),
		property("KillMode", "control-group"), property("SendSIGKILL", true),
		property("TasksMax", uint64(64)), property("MemoryMax", uint64(256<<20)),
		property("LimitCORE", uint64(0)), property("LimitCORESoft", uint64(0)),
		property("LimitNOFILE", uint64(256)), property("LimitNOFILESoft", uint64(256)),
		property("Environment", []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}),
		property("Restart", "no"), property("CollectMode", "inactive-or-failed"),
		property("StandardInput", "null"),
	}
}

type rootInventoryOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *rootInventoryOutput) Write(p []byte) (int, error) {
	n := len(p)
	if n > b.limit-b.buffer.Len() {
		b.overflow = true
		p = p[:b.limit-b.buffer.Len()]
	}
	_, err := b.buffer.Write(p)
	return n, err
}

// Keep diagnostics bounded and internal. Error strings never include native
// output, which may contain device identities or the helper's JSON payload.
type rootInventoryFailure struct {
	cause      error
	jobResult  string
	unitResult string
	exitCode   int32
	exitStatus int32
	diagnostic string
}

// Error names the systemd/D-Bus cause; the helper's stderr stays in diagnostic.
func (e *rootInventoryFailure) Error() string {
	if e.cause == nil {
		return "root inventory native unit failed"
	}
	return "root inventory native unit failed: " + e.cause.Error()
}
func (e *rootInventoryFailure) Unwrap() error { return e.cause }

// rootInventoryError names the failed stage of one root observation for the
// executor log. The RPC boundary still maps every instance to errInternal.
type rootInventoryError struct {
	stage        string
	unit         string
	err          error
	cleanup      error
	payloadBytes int
	violations   []string
}

func (e *rootInventoryError) Error() string { return "root inventory " + e.stage + " failed" }
func (e *rootInventoryError) Unwrap() []error {
	if e.cleanup == nil {
		return []error{e.err}
	}
	return []error{e.err, e.cleanup}
}

// logAttrs never includes the helper payload: only its size, schema field paths
// and rule IDs, systemd job/unit results, exit status and the bounded native
// stderr diagnostic.
func (e *rootInventoryError) logAttrs() []any {
	attrs := []any{"stage", e.stage, "error", e.err}
	if e.unit != "" {
		attrs = append(attrs, "unit", e.unit)
	}
	if e.cleanup != nil {
		attrs = append(attrs, "cleanup_error", e.cleanup)
	}
	if e.payloadBytes != 0 {
		attrs = append(attrs, "payload_bytes", e.payloadBytes)
	}
	if len(e.violations) != 0 {
		attrs = append(attrs, "violations", e.violations)
	}
	var failure *rootInventoryFailure
	if !errors.As(e.err, &failure) {
		return attrs
	}
	if failure.jobResult != "" {
		attrs = append(attrs, "job_result", failure.jobResult)
	}
	if failure.unitResult != "" {
		attrs = append(attrs, "unit_result", failure.unitResult)
	}
	switch failure.exitCode {
	case cldExited:
		attrs = append(attrs, "exit_status", failure.exitStatus)
	case cldKilled, cldDumped:
		attrs = append(attrs, "signal", unix.Signal(failure.exitStatus).String())
	}
	if failure.diagnostic != "" {
		attrs = append(attrs, "diagnostic", failure.diagnostic)
	}
	return attrs
}

// violationPaths reports at most eight field paths and rule IDs, never values.
func (s *Service) violationPaths(msg proto.Message) []string {
	var invalid *protovalidate.ValidationError
	if !errors.As(s.validator.Validate(msg), &invalid) {
		return nil
	}
	paths := make([]string, 0, min(len(invalid.Violations), 8))
	for _, violation := range invalid.Violations[:min(len(invalid.Violations), 8)] {
		paths = append(paths, protovalidate.FieldPathString(violation.Proto.GetField())+":"+violation.Proto.GetRuleId())
	}
	return paths
}

// rootInventoryDiagnostic keeps the native stderr diagnostic printable and
// bounded for one journal entry.
func rootInventoryDiagnostic(data []byte) string {
	const limit = 2 << 10
	if len(data) > limit {
		data = data[:limit]
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return '?'
		}
		return r
	}, strings.ToValidUTF8(strings.TrimSpace(string(data)), "?"))
}
