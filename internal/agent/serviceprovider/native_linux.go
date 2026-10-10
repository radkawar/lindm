//go:build linux

package serviceprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func (p *Provider) manager(ctx context.Context, method string, args ...any) *dbus.Call {
	// Pin the systemd unique owner for this connection. Never silently switch to
	// a replacement manager midway through an operation.
	return p.conn.Object(p.owner, managerPath).CallWithContext(ctx, managerInterface+"."+method, dbus.FlagNoAutoStart, args...)
}

func nativeReadError(operation string, err error) error {
	var native dbus.Error
	if errors.As(err, &native) {
		switch native.Name {
		case "org.freedesktop.systemd1.NoSuchUnit", "org.freedesktop.systemd1.LoadFailed", "org.freedesktop.systemd1.UnitMasked", "org.freedesktop.systemd1.InvalidName":
			return fmt.Errorf("%w: %s: %w", ErrUnsupported, operation, err)
		}
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (p *Provider) observe(ctx context.Context, unit string) (*resourcev1.SystemdServiceObservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var path dbus.ObjectPath
	if err := p.manager(ctx, "LoadUnit", unit).Store(&path); err != nil {
		return nil, nativeReadError("load service", err)
	}
	if !path.IsValid() || !strings.HasPrefix(string(path), "/org/freedesktop/systemd1/unit/") {
		return nil, fmt.Errorf("%w: invalid unit object path", ErrUnsupported)
	}
	object := p.conn.Object(p.owner, path)
	var unitProperties, serviceProperties map[string]dbus.Variant
	if err := object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, systemdName+".Unit").Store(&unitProperties); err != nil {
		return nil, nativeReadError("read unit properties", err)
	}
	var id string
	if err := property(unitProperties, "Id", &id); err != nil {
		return nil, err
	}
	if id != unit {
		return nil, fmt.Errorf("%w: %q resolves to canonical unit %q", ErrUnsupported, unit, id)
	}
	o := &resourcev1.SystemdServiceObservation{Unit: id}
	if err := property(unitProperties, "LoadState", &o.LoadState); err != nil {
		return nil, err
	}
	// LoadUnit may return a cached not-found object without a D-Bus error.
	// Such an object has no persistent unit file to query or manage.
	if o.LoadState != "loaded" {
		return nil, fmt.Errorf("%w: unit load state %q", ErrUnsupported, o.LoadState)
	}
	if err := object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, systemdName+".Service").Store(&serviceProperties); err != nil {
		return nil, nativeReadError("read service properties", err)
	}
	var fragment string
	var dropIns []string
	var job struct {
		ID   uint32
		Path dbus.ObjectPath
	}
	for _, field := range []struct {
		name string
		out  any
	}{
		{"ActiveState", &o.ActiveState}, {"SubState", &o.SubState},
		{"RefuseManualStart", &o.RefuseManualStart}, {"RefuseManualStop", &o.RefuseManualStop},
		{"NeedDaemonReload", &o.NeedDaemonReload}, {"Transient", &o.Transient},
		{"FragmentPath", &fragment}, {"DropInPaths", &dropIns}, {"Job", &job},
	} {
		if err := property(unitProperties, field.name, field.out); err != nil {
			return nil, err
		}
	}
	if err := property(serviceProperties, "Type", &o.ServiceType); err != nil {
		return nil, err
	}
	if err := property(serviceProperties, "RemainAfterExit", &o.RemainAfterExit); err != nil {
		return nil, err
	}
	o.JobPending = job.ID != 0 || job.Path != "/"
	if err := p.manager(ctx, "GetUnitFileState", unit).Store(&o.UnitFileState); err != nil {
		return nil, nativeReadError("read persistent enablement", err)
	}
	if err := supportedObservation(o); err != nil {
		return nil, err
	}
	var err error
	o.DefinitionSha256, err = definitionHash(ctx, fragment, dropIns)
	if err != nil {
		return nil, err
	}
	o.BootId, err = bootID()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o.ObservedAt = timestamppb.Now()
	o.FingerprintSha256 = fingerprint(o)
	if err := validateMessage(o); err != nil {
		return nil, err
	}
	return o, nil
}

func property(properties map[string]dbus.Variant, name string, out any) error {
	value, ok := properties[name]
	if !ok {
		return fmt.Errorf("%w: missing native property %s", ErrUnsupported, name)
	}
	if err := value.Store(out); err != nil {
		return fmt.Errorf("%w: native property %s: %v", ErrUnsupported, name, err)
	}
	return nil
}

func bootID() (string, error) {
	file, err := os.Open("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	value, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return "", err
	}
	if len(value) == 128 {
		return "", fmt.Errorf("%w: oversized boot ID", ErrUnsupported)
	}
	return strings.TrimSpace(string(value)), nil
}

// Apply rejects invalid/fabricated/stale plans before sending a native mutation.
// A drifting plan requires authorizeStart, called once after native preflight
// and job-subscription setup, immediately before its first mutation. The callback
// must durably authorize and consume the start; a plan alone is not authority.
// Once a mutation is submitted, cancellation/transport failure is uncertain; it
// never means systemd canceled the job, and no automatic retry is attempted.
func (p *Provider) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, authorizeStart func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	if err := ValidatePlan(plan); err != nil {
		return nil, err
	}
	if (plan.GetSystemdService().GetChangeEnablement() || plan.GetSystemdService().GetChangeRuntime()) && authorizeStart == nil {
		return nil, fmt.Errorf("%w: missing start authorization", ErrUnsupported)
	}
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if err := p.checkBinding(plan, true); err != nil {
		return nil, err
	}
	current, err := p.observe(ctx, plan.GetSystemdService().GetDesired().GetUnit())
	if err != nil {
		return nil, err
	}
	if err := checkFresh(plan, current); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	effected := false
	if plan.GetSystemdService().GetChangeEnablement() {
		if err := p.changeEnablement(ctx, plan.GetSystemdService().GetDesired(), authorizeStart); err != nil {
			return nil, err
		}
		effected = true
		// Before a second effect, check the actual first result and every other
		// precondition again. Do not start/stop after unexpected intervening drift.
		current, err = p.observe(ctx, plan.GetSystemdService().GetDesired().GetUnit())
		if err != nil {
			return nil, fmt.Errorf("%w: observe after enablement: %w", ErrOutcomeUnknown, err)
		}
		expected := proto.CloneOf(plan.GetSystemdService().GetBefore())
		if plan.GetSystemdService().GetDesired().GetEnablement() == resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED {
			expected.UnitFileState = "enabled"
		} else {
			expected.UnitFileState = "disabled"
		}
		if !bytes.Equal(fingerprint(expected), current.GetFingerprintSha256()) {
			result, err := verification(plan, current, p.incarnation)
			if err != nil {
				return nil, fmt.Errorf("%w: verify after enablement: %w", ErrOutcomeUnknown, err)
			}
			return result, fmt.Errorf("%w: unexpected state after enablement", ErrConflict)
		}
	}
	if plan.GetSystemdService().GetChangeRuntime() {
		if err := ctx.Err(); err != nil {
			if effected {
				return nil, fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
			}
			return nil, err
		}
		start := authorizeStart
		if effected {
			start = nil // The enablement effect already consumed this start.
		}
		err = p.changeRuntime(ctx, plan.GetSystemdService().GetDesired(), start)
		if err != nil {
			if errors.Is(err, ErrNotConverged) {
				result, observeErr := p.verify(ctx, plan)
				if observeErr != nil && !errors.Is(observeErr, ErrNotConverged) {
					return result, fmt.Errorf("%w: %w", ErrOutcomeUnknown, errors.Join(err, observeErr))
				}
				return result, err
			}
			if effected && !errors.Is(err, ErrOutcomeUnknown) {
				return nil, fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
			}
			return nil, err
		}
		effected = true
	}
	result, err := p.verify(ctx, plan)
	if err != nil && effected && !errors.Is(err, ErrNotConverged) {
		return result, fmt.Errorf("%w: post-effect verification: %w", ErrOutcomeUnknown, err)
	}
	return result, err
}

func (p *Provider) changeEnablement(ctx context.Context, desired *resourcev1.SystemdServiceDesired, authorizeStart func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := authorizeStart(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var call *dbus.Call
	if desired.GetEnablement() == resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED {
		call = p.manager(ctx, "EnableUnitFiles", []string{desired.GetUnit()}, false, false)
	} else {
		call = p.manager(ctx, "DisableUnitFiles", []string{desired.GetUnit()}, false)
	}
	if call.Err != nil {
		return fmt.Errorf("%w: change persistent enablement: %w", ErrOutcomeUnknown, call.Err)
	}
	// Persistent link changes invalidate systemd's loaded dependency graph.
	// Reload is the native counterpart of systemctl enable/disable; it can
	// incorporate other pending definitions too, not just this unit's links.
	// The caller re-observes and checks this unit's definition before runtime
	// effects. Failure here cannot claim that the preceding links were undone.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: reload after enablement: %w", ErrOutcomeUnknown, err)
	}
	if err := p.manager(ctx, "Reload").Err; err != nil {
		return fmt.Errorf("%w: reload after enablement: %w", ErrOutcomeUnknown, err)
	}
	// Replies only describe changes attempted. GetUnitFileState is the oracle.
	return nil
}

func (p *Provider) changeRuntime(ctx context.Context, desired *resourcev1.SystemdServiceDesired, authorizeStart func(context.Context) error) (resultErr error) {
	signals := make(chan *dbus.Signal, 32)
	p.conn.Signal(signals)
	defer p.conn.RemoveSignal(signals)
	// Older system buses accept arg2 matches but fail to deliver JobRemoved's
	// uoss body through them (observed on AlmaLinux 9). Match the authenticated
	// manager here and check the exact unit/job locally in jobResult instead.
	match := []dbus.MatchOption{
		dbus.WithMatchSender(p.owner), dbus.WithMatchObjectPath(managerPath),
		dbus.WithMatchInterface(managerInterface), dbus.WithMatchMember("JobRemoved"),
	}
	if err := p.conn.AddMatchSignalContext(ctx, match...); err != nil {
		return fmt.Errorf("install job match: %w", err)
	}
	submitted := false
	defer func() {
		// Removal is bounded independently of an abandoned operation. Removing
		// the local signal registration also joins default-handler senders.
		p.conn.RemoveSignal(signals)
		cleanup, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		stop := closeOnCancel(cleanup, p.socket)
		defer stop()
		if err := p.conn.RemoveMatchSignalContext(cleanup, match...); err != nil {
			_ = p.Close() // Private disconnect removes every match/subscription.
			cleanupErr := fmt.Errorf("remove job match: %w", err)
			if submitted {
				cleanupErr = fmt.Errorf("%w: %w", ErrOutcomeUnknown, cleanupErr)
			}
			resultErr = errors.Join(resultErr, cleanupErr)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	method := "StartUnit"
	if desired.GetRuntime() == resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE {
		method = "StopUnit"
	}
	if authorizeStart != nil {
		if err := authorizeStart(ctx); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var job dbus.ObjectPath
	submitted = true
	if err := p.manager(ctx, method, desired.GetUnit(), "fail").Store(&job); err != nil {
		return fmt.Errorf("%w: submit %s: %w", ErrOutcomeUnknown, method, err)
	}
	if !job.IsValid() || !strings.HasPrefix(string(job), "/org/freedesktop/systemd1/job/") {
		return fmt.Errorf("%w: invalid returned job path", ErrOutcomeUnknown)
	}
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: await native job: %w", ErrOutcomeUnknown, ctx.Err())
		case <-p.conn.Context().Done():
			return fmt.Errorf("%w: bus disconnected awaiting job", ErrOutcomeUnknown)
		case signal, ok := <-signals:
			if !ok {
				return fmt.Errorf("%w: job signal stream closed", ErrOutcomeUnknown)
			}
			result, matches := jobResult(signal, p.owner, job, desired.GetUnit())
			if !matches {
				continue
			}
			if result != "done" {
				return fmt.Errorf("%w: native job completed with %q", ErrNotConverged, result)
			}
			return nil
		}
	}
}

func jobResult(signal *dbus.Signal, owner string, job dbus.ObjectPath, unit string) (string, bool) {
	if signal == nil || signal.Sender != owner || signal.Path != managerPath || signal.Name != managerInterface+".JobRemoved" || len(signal.Body) != 4 {
		return "", false
	}
	id, idOK := signal.Body[0].(uint32)
	path, pathOK := signal.Body[1].(dbus.ObjectPath)
	name, nameOK := signal.Body[2].(string)
	result, resultOK := signal.Body[3].(string)
	if !idOK || !pathOK || !nameOK || !resultOK || path != job || name != unit ||
		string(path) != "/org/freedesktop/systemd1/job/"+strconv.FormatUint(uint64(id), 10) || len(result) > 64 {
		return "", false
	}
	return result, true
}
