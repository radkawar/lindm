package loadlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/devlab"
	"lindm/internal/labexec"
	"lindm/internal/rpcreason"
)

// HAOptions selects a bounded replicated-topology qualification run. There is
// no endpoint or credential override: the lane always owns its topology.
type HAOptions struct {
	Repository    string
	ServerBinary  string
	UpgradeBinary string
	Devices       int
	PhaseDuration time.Duration
	Seed          uint64
}

// HAEvent is one orchestrated fault or lifecycle step.
type HAEvent struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Target string    `json:"target"`
	Detail string    `json:"detail,omitempty"`
}

// HAPhase records protocol outcomes between two orchestration boundaries.
type HAPhase struct {
	Name               string               `json:"name"`
	StartedAt          time.Time            `json:"started_at"`
	FinishedAt         time.Time            `json:"finished_at"`
	RPC                map[string]RPCResult `json:"rpc"`
	AcceptedActions    int                  `json:"accepted_actions"`
	CompletedActions   int                  `json:"completed_actions"`
	ServiceExecutions  int                  `json:"service_executions"`
	InFlightAtBoundary int                  `json:"in_flight_restarts_at_start"`
}

// HACheck is one acceptance criterion with its observed evidence.
type HACheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// HAResult is the persisted, nonsecret lane record.
type HAResult struct {
	StartedAt       time.Time                `json:"started_at"`
	FinishedAt      time.Time                `json:"finished_at"`
	GoVersion       string                   `json:"go_version"`
	Hardware        map[string]string        `json:"hardware"`
	ServerSHA256    string                   `json:"server_sha256"`
	UpgradeSHA256   string                   `json:"upgrade_sha256"`
	GeneratorSHA256 string                   `json:"generator_sha256"`
	ServerVersion   string                   `json:"server_version"`
	UpgradeVersion  string                   `json:"upgrade_version"`
	Options         HAOptions                `json:"options"`
	Environment     devlab.HAEnvironment     `json:"environment"`
	Events          []HAEvent                `json:"events"`
	Phases          []HAPhase                `json:"phases"`
	Failover        devlab.HAFailover        `json:"database_failover"`
	Instances       []devlab.HAInstanceState `json:"final_instances"`
	Leadership      HALeadership             `json:"leadership"`
	Actions         HAActionSummary          `json:"actions"`
	Admin           HAAdminSummary           `json:"admin"`
	Violations      []string                 `json:"violations"`
	ProxyHealth     []string                 `json:"proxy_health_transitions"`
	Checks          []HACheck                `json:"checks"`
	Passed          bool                     `json:"passed"`
	Failure         string                   `json:"failure,omitempty"`
	InFlightAtCrash int                      `json:"in_flight_restarts_at_crash"`
	// ReplicaErrors holds bounded ERROR log messages of replicas that exited
	// without a laboratory signal.
	ReplicaErrors []string `json:"replica_errors,omitempty"`
}

// HAActionSummary reconciles admin-accepted restarts with device and server.
type HAActionSummary struct {
	Accepted            int      `json:"accepted"`
	DeviceExecuted      int      `json:"device_executed"`
	DuplicateExecutions int      `json:"duplicate_executions"`
	ServerSucceeded     int      `json:"server_succeeded"`
	ServerActions       int      `json:"server_actions"`
	Expired             int      `json:"expired"`
	Lost                []string `json:"lost,omitempty"`
	Unaccepted          []string `json:"unaccepted,omitempty"`
	ServiceExecutions   int      `json:"service_executions"`
	ServiceDuplicates   int      `json:"service_duplicates"`
	InterruptedReports  int      `json:"interrupted_reports"`
	// Service assignments are accepted admin work dispatched as signed
	// resource actions; convergence is read back from the server.
	AssignmentsAccepted  int      `json:"assignments_accepted"`
	AssignmentsConverged int      `json:"assignments_converged"`
	ServiceLost          []string `json:"service_lost,omitempty"`
}

// HAAdminSummary counts administrative mutation outcomes.
type HAAdminSummary struct {
	Requests         int            `json:"requests"`
	AmbiguousRetries int            `json:"ambiguous_retries"`
	Rejections       map[string]int `json:"rejections"`
}

type haDevice struct {
	*simulatedDevice
	restart *pendingRestart
}

type restartRecord struct {
	device     string
	accepted   bool
	executions int
	executed   bool
	finished   bool
	boot       string
}

// haLedger is the devices' combined effect journal and the admin acceptance log.
type haLedger struct {
	mu                sync.Mutex
	restarts          map[string]*restartRecord
	requests          map[string]string // request ID -> action ID
	services          map[string]int
	serviceByDevice   map[string][]string
	assignments       map[string]string // device ID -> accepted assignment ID
	inflight          map[string]bool
	busy              map[string]bool
	violations        []string
	duplicates        int
	serviceDuplicates int
	interrupted       int
}

func newHALedger() *haLedger {
	return &haLedger{restarts: make(map[string]*restartRecord), requests: make(map[string]string), services: make(map[string]int), serviceByDevice: make(map[string][]string),
		assignments: make(map[string]string), inflight: make(map[string]bool), busy: make(map[string]bool)}
}

func (l *haLedger) violation(message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.violations) < 64 {
		l.violations = append(l.violations, time.Now().UTC().Format(time.RFC3339Nano)+" "+message)
	}
}

func (l *haLedger) accept(requestID, device, action string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if previous, ok := l.requests[requestID]; ok && previous != action {
		return fmt.Errorf("request %s accepted as two actions", requestID)
	}
	l.requests[requestID] = action
	record := l.restarts[action]
	if record == nil {
		record = &restartRecord{device: device}
		l.restarts[action] = record
	}
	record.accepted = true
	if !record.finished {
		l.busy[device] = true
	}
	return nil
}

func (l *haLedger) idle(device string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.busy[device]
}

func (l *haLedger) restartSeen(action string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	record := l.restarts[action]
	return record != nil && (record.finished || record.executions > 0)
}

func (l *haLedger) executeRestart(device, action string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	record := l.restarts[action]
	if record == nil {
		record = &restartRecord{device: device}
		l.restarts[action] = record
	}
	record.executions++
	if record.executions > 1 {
		l.duplicates++
		return errors.Join(errProtocolViolation, fmt.Errorf("restart %s executed %d times", action, record.executions))
	}
	l.inflight[action] = true
	return nil
}

func (l *haLedger) finishRestart(action string, executed bool, boot string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	record := l.restarts[action]
	if record == nil {
		return
	}
	record.finished, record.executed, record.boot = true, executed, boot
	delete(l.inflight, action)
	delete(l.busy, record.device)
}

func (l *haLedger) reportInterrupted() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.interrupted++
}

func (l *haLedger) serviceEffect(device, action string, _ uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.services[action]++
	l.serviceByDevice[device] = append(l.serviceByDevice[device], action)
	if l.services[action] > 1 {
		l.serviceDuplicates++
		return errors.Join(errProtocolViolation, fmt.Errorf("service action %s executed %d times", action, l.services[action]))
	}
	return nil
}

func (l *haLedger) assign(device, assignment string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if previous, ok := l.assignments[device]; ok && previous != assignment {
		return fmt.Errorf("device %s accepted two initial assignments", device)
	}
	l.assignments[device] = assignment
	return nil
}

func (l *haLedger) counts() (accepted, completed, services, inflight int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, record := range l.restarts {
		if record.accepted {
			accepted++
			if record.finished {
				completed++
			}
		}
	}
	for _, n := range l.services {
		services += n
	}
	return accepted, completed, services, len(l.inflight)
}

type haRun struct {
	*runner
	options  HAOptions
	ledger   *haLedger
	random   *rand.Rand
	randomMu sync.Mutex
	events   []HAEvent
	eventsMu sync.Mutex
	devices  []*haDevice
	admin    HAAdminSummary
	adminMu  sync.Mutex
	holders  *holderSampler
	stopping atomic.Bool
}

func (h *haRun) executionDelay() time.Duration {
	h.randomMu.Lock()
	defer h.randomMu.Unlock()
	return time.Second + time.Duration(h.random.Int64N(int64(2*time.Second)))
}

func (h *haRun) jitter(base time.Duration) time.Duration {
	h.randomMu.Lock()
	defer h.randomMu.Unlock()
	return jitter(h.random, base)
}

func (h *haRun) event(kind, target, detail string) {
	h.eventsMu.Lock()
	defer h.eventsMu.Unlock()
	h.events = append(h.events, HAEvent{At: time.Now().UTC(), Kind: kind, Target: target, Detail: detail})
}

// classify keeps retryable RPC faults in metrics and records anything else.
func (h *haRun) classify(ctx context.Context, d *haDevice, operation string, err error) {
	if err == nil || ctx.Err() != nil {
		return
	}
	var rpc *connect.Error
	if !errors.Is(err, errProtocolViolation) && errors.As(err, &rpc) {
		if operation == "restart" && d.restart != nil && d.restart.executed {
			h.ledger.reportInterrupted()
		}
		return
	}
	h.ledger.violation(fmt.Sprintf("device %s %s: %v", d.id, operation, err))
}

func (h *haRun) deviceLoop(ctx context.Context, d *haDevice) {
	nextHeartbeat, nextTrust, nextDispatch := time.Now(), time.Now().Add(h.jitter(30*time.Second)), time.Now()
	for ctx.Err() == nil {
		now := time.Now()
		if !now.Before(nextHeartbeat) {
			_, err := d.client.GetSyncState(ctx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: d.epoch}))
			h.classify(ctx, d, "heartbeat", err)
			nextHeartbeat = now.Add(h.jitter(10 * time.Second))
		}
		if !now.Before(nextTrust) {
			h.classify(ctx, d, "trust", h.syncTrust(ctx, d.simulatedDevice))
			nextTrust = now.Add(h.jitter(30 * time.Second))
		}
		if !now.Before(nextDispatch) {
			h.classify(ctx, d, "service", h.dispatch(ctx, d.simulatedDevice))
			nextDispatch = now.Add(h.jitter(5 * time.Second))
		}
		h.classify(ctx, d, "restart", h.restartAction(ctx, d))
		timer := time.NewTimer(h.jitter(time.Second))
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func restartSpec() *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}}
}

// ambiguous reports whether a mutation's outcome is unknown and must be retried
// with the same request ID. Any other error is a definitive rejection.
func ambiguous(err error) bool {
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeUnknown, connect.CodeInternal, connect.CodeAborted:
		return true
	default:
		return false
	}
}

// adminLoop issues two streams of accepted work throughout every fault: one
// restart per second for an idle device, and the first service assignment of
// each device spread across the planned run. Ambiguous outcomes are retried
// with the exact same request until the server answers definitively.
func (h *haRun) adminLoop(ctx context.Context) {
	next, assigned := 0, 0
	// The orchestrated phases total 4.5 phase durations; finishing assignments
	// within four leaves the last one inside the second rolling step.
	assignEvery := max(time.Second, h.options.PhaseDuration*4/time.Duration(len(h.devices)))
	nextAssignment := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for !h.stopping.Load() && ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if assigned < len(h.devices) && !time.Now().Before(nextAssignment) {
			h.assign(ctx, h.devices[assigned])
			assigned++
			nextAssignment = time.Now().Add(assignEvery)
		}
		var target *haDevice
		for range h.devices {
			candidate := h.devices[next%len(h.devices)]
			next++
			if h.ledger.idle(candidate.id) {
				target = candidate
				break
			}
		}
		if target == nil {
			continue
		}
		request := &adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: target.id, EnrollmentGeneration: target.generation, Spec: restartSpec(),
			ExpiresAt: timestamppb.New(time.Now().Add(10 * time.Minute)), Reason: "HA laboratory restart"}
		h.mutate(ctx, "CreateDeviceAction", func(ctx context.Context) error {
			response, err := h.owner.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
			if err != nil {
				return err
			}
			action := response.Msg.GetAction()
			if action.GetDeviceId() != request.GetDeviceId() || action.GetSpec().GetRestart() == nil {
				h.ledger.violation("accepted restart does not bind its request")
				return nil
			}
			if err := h.ledger.accept(request.GetRequestId(), request.GetDeviceId(), action.GetActionId()); err != nil {
				h.ledger.violation(err.Error())
			}
			return nil
		})
	}
}

func (h *haRun) assign(ctx context.Context, d *haDevice) {
	request := &adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: d.id, Target: &adminv1.ResourceAssignmentTarget{ProfileId: h.profile.GetProfileId(), RevisionId: h.profile.GetRevisionId()}, Reason: "HA laboratory service assignment"}
	h.mutate(ctx, "SetResourceAssignment", func(ctx context.Context) error {
		response, err := h.owner.Admin.SetResourceAssignment(ctx, connect.NewRequest(request))
		if err != nil {
			return err
		}
		assignment := response.Msg.GetAssignment()
		if assignment.GetDeviceId() != d.id || assignment.GetRevisionId() != h.profile.GetRevisionId() {
			h.ledger.violation("accepted assignment does not bind its request")
			return nil
		}
		if err := h.ledger.assign(d.id, assignment.GetAssignmentId()); err != nil {
			h.ledger.violation(err.Error())
		}
		return nil
	})
}

// mutate retries one administrative request while its outcome is ambiguous.
func (h *haRun) mutate(ctx context.Context, name string, call func(context.Context) error) {
	h.adminMu.Lock()
	h.admin.Requests++
	h.adminMu.Unlock()
	deadline := time.Now().Add(3 * time.Minute)
	for ctx.Err() == nil {
		started := time.Now()
		attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := call(attempt)
		cancel()
		h.metrics.observe(name, time.Since(started), err)
		if err == nil || ctx.Err() != nil {
			return
		}
		if !ambiguous(err) || time.Now().After(deadline) {
			reason := name + ":" + connect.CodeOf(err).String()
			var failure *connect.Error
			if errors.As(err, &failure) && rpcreason.Get(failure) != "" {
				reason += "/" + rpcreason.Get(failure)
			}
			h.adminMu.Lock()
			if h.admin.Rejections == nil {
				h.admin.Rejections = make(map[string]int)
			}
			h.admin.Rejections[reason]++
			h.adminMu.Unlock()
			return
		}
		h.adminMu.Lock()
		h.admin.AmbiguousRetries++
		h.adminMu.Unlock()
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

// RunHA qualifies the replicated topology: two lindmd replicas behind HAProxy,
// a synchronous PostgreSQL standby, an instance crash during dispatch, standby
// promotion and an N to N+1 rolling upgrade under continuous work. Device
// effects are simulated; the control plane, database and balancer are real.
func RunHA(ctx context.Context, options HAOptions) (result HAResult, resultErr error) {
	if options.Devices == 0 {
		options.Devices = 24
	}
	if options.PhaseDuration == 0 {
		options.PhaseDuration = time.Minute
	}
	if options.Devices < 4 || options.Devices > 256 || options.PhaseDuration < 20*time.Second || options.PhaseDuration > 30*time.Minute || options.ServerBinary == "" || options.UpgradeBinary == "" {
		return result, errors.New("ha: requires 4..256 devices, a 20s..30m phase and both release binaries")
	}
	result = HAResult{StartedAt: time.Now().UTC(), Options: options, GoVersion: runtime.Version()}
	defer func() {
		result.FinishedAt = time.Now().UTC()
		if resultErr != nil {
			result.Failure = resultErr.Error()
			result.Passed = false
		}
	}()
	var err error
	if result.Hardware, err = hardware(ctx); err != nil {
		return result, err
	}
	if result.ServerSHA256, err = binaryDigest(options.ServerBinary); err != nil {
		return result, err
	}
	if result.UpgradeSHA256, err = binaryDigest(options.UpgradeBinary); err != nil {
		return result, err
	}
	executable, err := os.Executable()
	if err != nil {
		return result, err
	}
	if result.GeneratorSHA256, err = binaryDigest(executable); err != nil {
		return result, err
	}
	if result.ServerVersion, err = binaryVersion(ctx, options.ServerBinary); err != nil {
		return result, err
	}
	if result.UpgradeVersion, err = binaryVersion(ctx, options.UpgradeBinary); err != nil {
		return result, err
	}
	if result.ServerSHA256 == result.UpgradeSHA256 || result.ServerVersion == result.UpgradeVersion {
		return result, errors.New("ha: the upgrade binary must be a distinct release")
	}
	// Devices enroll unassigned; the admin stream assigns them across the faults.
	h := &haRun{runner: &runner{options: Options{Packages: 50, AssignmentPercent: 0, EnrollmentWorkers: 8, Seed: options.Seed}, metrics: &measurements{}}, options: options, ledger: newHALedger(), random: rand.New(rand.NewPCG(options.Seed, options.Seed^0x9e3779b97f4a7c15))}
	h.effects = h.ledger.serviceEffect
	h.fixture, err = devlab.OpenHAAuthorityFixture(ctx, options.Repository, options.ServerBinary)
	if err != nil {
		return result, fmt.Errorf("open HA topology: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, h.fixture.Close()) }()
	if result.Environment, err = h.fixture.HAEnvironment(); err != nil {
		return result, err
	}
	for _, state := range h.fixture.HAInstances() {
		h.event("start", state.Name, state.Binary)
	}
	if err := h.prepare(ctx); err != nil {
		return result, fmt.Errorf("prepare HA authority: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, h.owner.Close(cleanup))
	}()
	defer h.enrollmentTransport.CloseIdleConnections()
	h.holders = newHolderSampler(h.fixture)
	samplerCtx, stopSampler := context.WithCancel(ctx)
	samplerDone := make(chan struct{})
	go func() {
		defer close(samplerDone)
		h.holders.run(samplerCtx)
	}()
	defer func() {
		stopSampler()
		<-samplerDone
	}()
	enrolled, err := h.enrollBatch(ctx, 0, options.Devices)
	for _, d := range enrolled {
		if d != nil {
			h.devices = append(h.devices, &haDevice{simulatedDevice: d})
		}
	}
	defer func() {
		for _, d := range h.devices {
			d.close()
		}
	}()
	if err != nil {
		return result, fmt.Errorf("enroll HA devices: %w", err)
	}
	h.metrics.snapshot(true)
	workCtx, stopWork := context.WithCancel(ctx)
	var workers sync.WaitGroup
	for _, d := range h.devices {
		workers.Go(func() { h.deviceLoop(workCtx, d) })
	}
	adminDone := make(chan struct{})
	go func() {
		defer close(adminDone)
		h.adminLoop(workCtx)
	}()
	stopAll := func() {
		h.stopping.Store(true)
		stopWork()
		<-adminDone
		workers.Wait()
	}
	defer func() {
		if workCtx.Err() == nil {
			stopAll()
		}
	}()
	phaseErr := h.orchestrate(ctx, &result)
	if phaseErr == nil {
		phaseErr = h.quiesce(ctx, &result)
	}
	stopAll()
	result.Events = slices.Clone(h.events)
	if phaseErr != nil {
		result.Instances = h.fixture.HAInstances()
		result.ReplicaErrors = h.replicaErrors()
		return result, phaseErr
	}
	return result, h.verify(ctx, &result)
}

// replicaErrors returns the last ERROR messages of replicas that are not running.
func (h *haRun) replicaErrors() []string {
	var errorsFound []string
	for _, instance := range h.fixture.HAInstances() {
		if instance.Running {
			continue
		}
		data, err := h.fixture.HAInstanceLog(instance.Name)
		if err != nil {
			errorsFound = append(errorsFound, instance.Name+": log unavailable")
			continue
		}
		var lines []string
		for _, line := range strings.Split(string(data), "\n") {
			var entry struct {
				Level, Msg, Err string
				Error           string `json:"error"`
			}
			if json.Unmarshal([]byte(line), &entry) == nil && entry.Level == "ERROR" {
				lines = append(lines, strings.TrimSpace(fmt.Sprintf("%s: %s %s %s", instance.Name, entry.Msg, entry.Err, entry.Error)))
			} else if strings.HasPrefix(line, "lindmd: ") {
				lines = append(lines, instance.Name+": "+line)
			}
		}
		errorsFound = append(errorsFound, instance.Name+": "+instance.Exit)
		errorsFound = append(errorsFound, lines[max(0, len(lines)-10):]...)
	}
	return errorsFound
}

func binaryVersion(ctx context.Context, binary string) (string, error) {
	output := nativeexec.NewBuffer(4 << 10)
	err := labexec.Run(ctx, labexec.Command{Path: binary, Args: []string{"version"}, Stdout: output, Timeout: 10 * time.Second})
	if err == nil && output.Truncated() {
		err = errors.New("output exceeds limit")
	}
	if err != nil {
		return "", fmt.Errorf("read %s version: %w", binary, err)
	}
	return strings.TrimSpace(output.String()), nil
}

// phase runs the workload for one interval and records its metrics.
func (h *haRun) phase(ctx context.Context, result *HAResult, name string, duration time.Duration, step func(context.Context) error) error {
	_, _, _, inflight := h.ledger.counts()
	phase := HAPhase{Name: name, StartedAt: time.Now().UTC(), InFlightAtBoundary: inflight}
	acceptedBefore, completedBefore, servicesBefore, _ := h.ledger.counts()
	var err error
	if step != nil {
		err = step(ctx)
	}
	if err == nil && duration > 0 {
		timer := time.NewTimer(duration)
		select {
		case <-ctx.Done():
			timer.Stop()
			err = ctx.Err()
		case <-timer.C:
		}
	}
	accepted, completed, services, _ := h.ledger.counts()
	phase.FinishedAt = time.Now().UTC()
	phase.RPC = h.metrics.snapshot(true)
	phase.AcceptedActions, phase.CompletedActions, phase.ServiceExecutions = accepted-acceptedBefore, completed-completedBefore, services-servicesBefore
	result.Phases = append(result.Phases, phase)
	if err != nil {
		return fmt.Errorf("HA phase %s: %w", name, err)
	}
	return nil
}

func (h *haRun) orchestrate(ctx context.Context, result *HAResult) error {
	duration := h.options.PhaseDuration
	if err := h.phase(ctx, result, "steady", duration, nil); err != nil {
		return err
	}
	// Crash a replica only while restarts are executing but unreported. Freeze
	// it first so requests routed to it are in flight when SIGKILL lands.
	if err := h.phase(ctx, result, "instance-crash", duration, func(ctx context.Context) error {
		if err := h.waitInFlight(ctx); err != nil {
			return err
		}
		_, _, _, inflight := h.ledger.counts()
		result.InFlightAtCrash = inflight
		if err := h.fixture.FreezeHAInstance("a"); err != nil {
			return err
		}
		h.event("freeze", "a", fmt.Sprintf("SIGSTOP with %d restarts executing; requests routed to a stay in flight", inflight))
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if err := h.fixture.KillHAInstance("a"); err != nil {
			return err
		}
		h.event("kill", "a", "SIGKILL")
		return nil
	}); err != nil {
		return err
	}
	if err := h.phase(ctx, result, "instance-restart", duration/2, func(ctx context.Context) error {
		if err := h.fixture.StartHAInstance(ctx, "a", h.options.ServerBinary); err != nil {
			return err
		}
		h.event("start", "a", "supervisor restart, same release")
		return nil
	}); err != nil {
		return err
	}
	if err := h.phase(ctx, result, "database-failover", duration, func(ctx context.Context) error {
		if err := h.waitInFlight(ctx); err != nil {
			return err
		}
		failover, err := h.fixture.FailOverHADatabase(ctx)
		result.Failover = failover
		if err != nil {
			return err
		}
		h.event("kill", failover.FailedNode, "primary container SIGKILL")
		h.event("promote", failover.PromotedNode, "pg_ctl promote")
		return nil
	}); err != nil {
		return err
	}
	for _, name := range devlab.HAInstanceNames {
		if err := h.phase(ctx, result, "rolling-upgrade-"+name, duration/2, func(ctx context.Context) error {
			for _, instance := range h.fixture.HAInstances() {
				if instance.Name == name && !instance.Running {
					return fmt.Errorf("replica %s exited without a laboratory signal: %s", name, instance.Exit)
				}
			}
			if err := h.fixture.StopHAInstance(name); err != nil {
				return err
			}
			h.event("stop", name, "SIGTERM drain")
			if err := h.fixture.StartHAInstance(ctx, name, h.options.UpgradeBinary); err != nil {
				return err
			}
			h.event("start", name, "upgrade release")
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (h *haRun) waitInFlight(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		if _, _, _, inflight := h.ledger.counts(); inflight > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("no restart was in flight to interrupt")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// quiesce stops new admission and requires every accepted restart to finish.
func (h *haRun) quiesce(ctx context.Context, result *HAResult) error {
	return h.phase(ctx, result, "quiesce", 0, func(ctx context.Context) error {
		h.stopping.Store(true)
		h.event("quiesce", "admin", "stop new restarts")
		ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		for {
			accepted, completed, _, _ := h.ledger.counts()
			if accepted == completed {
				return nil
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("%d accepted restarts did not finish", accepted-completed)
			case <-time.After(250 * time.Millisecond):
			}
		}
	})
}

// verify reconciles the device journals, admin acceptance and server records.
func (h *haRun) verify(ctx context.Context, result *HAResult) error {
	instances := h.fixture.HAInstances()
	result.Instances = instances
	leadership, err := h.leadership(ctx, result)
	if err != nil {
		return err
	}
	result.Leadership = leadership
	proxyLog, err := h.fixture.HAProxyLog(ctx)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(proxyLog, "\n") {
		if strings.Contains(line, " is DOWN") || strings.Contains(line, " is UP") {
			result.ProxyHealth = append(result.ProxyHealth, strings.TrimSpace(line))
		}
	}
	h.adminMu.Lock()
	result.Admin = h.admin
	h.adminMu.Unlock()
	l := h.ledger
	l.mu.Lock()
	result.Violations = slices.Clone(l.violations)
	summary := HAActionSummary{DuplicateExecutions: l.duplicates, ServiceDuplicates: l.serviceDuplicates, InterruptedReports: l.interrupted}
	for _, n := range l.services {
		summary.ServiceExecutions += n
	}
	executedServices := make(map[string]map[string]bool, len(l.serviceByDevice))
	for device, actions := range l.serviceByDevice {
		executedServices[device] = make(map[string]bool, len(actions))
		for _, action := range actions {
			executedServices[device][action] = true
		}
	}
	assignments := maps.Clone(l.assignments)
	records := make(map[string]restartRecord, len(l.restarts))
	perDevice := make(map[string]int)
	for action, record := range l.restarts {
		records[action] = *record
		if record.accepted {
			summary.Accepted++
			perDevice[record.device]++
		}
		if record.executions > 0 {
			summary.DeviceExecuted++
		}
	}
	l.mu.Unlock()
	for _, d := range h.devices {
		actions, err := h.deviceActions(ctx, d.id)
		if err != nil {
			return err
		}
		summary.ServerActions += len(actions)
		for _, action := range actions {
			record, ok := records[action.GetActionId()]
			if !ok || !record.accepted {
				summary.Unaccepted = append(summary.Unaccepted, action.GetActionId())
				continue
			}
			state := action.GetStatus().GetState()
			switch {
			case state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED && record.executions == 1 && record.executed && action.GetStatus().GetVerification().GetBootId() == record.boot:
				summary.ServerSucceeded++
			case state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED && record.executions == 0:
				summary.Expired++
				summary.Lost = append(summary.Lost, action.GetActionId()+" expired before start")
			default:
				summary.Lost = append(summary.Lost, fmt.Sprintf("%s server=%s executions=%d", action.GetActionId(), state, record.executions))
			}
		}
		if len(actions) != perDevice[d.id] {
			summary.Lost = append(summary.Lost, fmt.Sprintf("device %s server actions %d != accepted %d", d.id, len(actions), perDevice[d.id]))
		}
	}
	if err := h.verifyServices(ctx, &summary, assignments, executedServices); err != nil {
		return err
	}
	result.Actions = summary
	h.check(result)
	return nil
}

// verifyServices reads each device's server resource state back and requires
// the accepted head, a converged resource and exactly-once device execution of
// every start the server authorized.
func (h *haRun) verifyServices(ctx context.Context, summary *HAActionSummary, assignments map[string]string, executed map[string]map[string]bool) error {
	for _, d := range h.devices {
		response, err := h.owner.Admin.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: d.id}))
		if err != nil {
			return fmt.Errorf("read device resource state: %w", err)
		}
		state := response.Msg
		assignment, accepted := assignments[d.id]
		if !accepted {
			if state.GetAssignment() != nil || len(executed[d.id]) > 0 {
				summary.ServiceLost = append(summary.ServiceLost, "device "+d.id+" has unaccepted service work")
			}
			continue
		}
		summary.AssignmentsAccepted++
		var problems []string
		if state.GetAssignment().GetAssignmentId() != assignment {
			problems = append(problems, "head differs from accepted assignment")
		}
		if len(state.GetResources()) == 0 {
			problems = append(problems, "no resources")
		}
		for _, resource := range state.GetResources() {
			latest := resource.GetLatestAction()
			if resource.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_SUCCEEDED || latest.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED || !executed[d.id][latest.GetActionId()] {
				problems = append(problems, fmt.Sprintf("resource %s disposition %s latest %s", resource.GetResourceId(), resource.GetDisposition(), latest.GetStatus().GetState()))
			}
		}
		listed := make(map[string]bool, len(state.GetRecentActions()))
		for _, recent := range state.GetRecentActions() {
			action := recent.GetAction()
			listed[action.GetActionId()] = true
			if action.GetStartAuthorizedAt() != nil && !executed[d.id][action.GetActionId()] {
				problems = append(problems, "server authorized an unexecuted start "+action.GetActionId())
			}
		}
		for action := range executed[d.id] {
			if !listed[action] {
				problems = append(problems, "device executed an action the server does not list "+action)
			}
		}
		if len(problems) > 0 {
			summary.ServiceLost = append(summary.ServiceLost, "device "+d.id+": "+strings.Join(problems, "; "))
			continue
		}
		summary.AssignmentsConverged++
	}
	return nil
}

func (h *haRun) deviceActions(ctx context.Context, device string) ([]*adminv1.DeviceAction, error) {
	var actions []*adminv1.DeviceAction
	token := ""
	for {
		response, err := h.owner.Admin.GetDeviceActions(ctx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: device, PageSize: 200, PageToken: token}))
		if err != nil {
			return nil, fmt.Errorf("list device actions: %w", err)
		}
		actions = append(actions, response.Msg.GetActions()...)
		token = response.Msg.GetNextPageToken()
		if token == "" {
			return actions, nil
		}
	}
}

func (h *haRun) check(result *HAResult) {
	add := func(name string, passed bool, detail string, args ...any) {
		result.Checks = append(result.Checks, HACheck{Name: name, Passed: passed, Detail: fmt.Sprintf(detail, args...)})
	}
	crash := phaseNamed(result.Phases, "instance-crash")
	deviceErrors := uint64(0)
	for name, rpc := range crash.RPC {
		if name != "CreateDeviceAction" && name != "SetResourceAssignment" {
			deviceErrors += rpc.Errors
		}
	}
	add("crash_interrupted_dispatch", result.InFlightAtCrash > 0 && deviceErrors > 0, "%d restarts executing at SIGKILL; %d device RPCs interrupted by the frozen-then-killed replica", result.InFlightAtCrash, deviceErrors)
	replication := result.Failover.ReplicationBeforeFailure
	synchronous := false
	for _, row := range replication {
		synchronous = synchronous || (row.ApplicationName == "lindm_standby" && row.SyncState == "sync" && row.State == "streaming")
	}
	add("synchronous_standby_promoted", synchronous && !result.Failover.WritableAt.IsZero(), "standby synchronous before failure=%t; writable %s after primary kill", synchronous, result.Failover.WritableAt.Sub(result.Failover.KilledAt))
	upgraded := 0
	for _, instance := range result.Instances {
		if instance.Running && instance.BinarySHA256 == result.UpgradeSHA256 {
			upgraded++
		}
	}
	add("rolling_upgrade_complete", upgraded == len(devlab.HAInstanceNames), "%d of %d replicas running %s", upgraded, len(devlab.HAInstanceNames), result.UpgradeVersion)
	a := result.Actions
	add("no_duplicate_effects", a.DuplicateExecutions == 0 && a.ServiceDuplicates == 0 && len(a.Unaccepted) == 0, "%d duplicate restarts, %d duplicate service executions, %d unaccepted server actions", a.DuplicateExecutions, a.ServiceDuplicates, len(a.Unaccepted))
	add("no_lost_actions", a.Accepted > 0 && a.ServerSucceeded == a.Accepted && len(a.Lost) == 0, "%d accepted, %d server-verified succeeded, %d lost", a.Accepted, a.ServerSucceeded, len(a.Lost))
	add("service_assignments_converged", a.AssignmentsAccepted == len(h.devices) && a.AssignmentsConverged == a.AssignmentsAccepted && len(a.ServiceLost) == 0, "%d of %d devices assigned; %d converged with exactly-once signed execution; %d lost", a.AssignmentsAccepted, len(h.devices), a.AssignmentsConverged, len(a.ServiceLost))
	add("no_protocol_violations", len(result.Violations) == 0, "%d violations", len(result.Violations))
	add("no_definitive_admin_rejections", len(result.Admin.Rejections) == 0, "%d requests, %d ambiguous retries, rejections %v", result.Admin.Requests, result.Admin.AmbiguousRetries, result.Admin.Rejections)
	ld := result.Leadership
	add("single_leader_jobs", ld.MaxOverlapSeconds <= maxLeadershipOverlap.Seconds() && ld.OverlapsOutsideFailover == 0, "max overlap %.1fs, %d overlaps outside database failover", ld.MaxOverlapSeconds, ld.OverlapsOutsideFailover)
	add("jobs_recovered", ld.AllJobsHeldAtEnd && ld.MaxGapSeconds <= maxLeadershipGap.Seconds(), "all exclusive jobs held at end=%t; longest unheld gap %.1fs", ld.AllJobsHeldAtEnd, ld.MaxGapSeconds)
	unexpected := 0
	for _, instance := range result.Instances {
		if !instance.Running {
			unexpected++
		}
	}
	add("replicas_survived_database_failover", unexpected == 0, "%d replicas not running at end", unexpected)
	result.Passed = true
	for _, check := range result.Checks {
		result.Passed = result.Passed && check.Passed
	}
}

func phaseNamed(phases []HAPhase, name string) HAPhase {
	for _, phase := range phases {
		if phase.Name == name {
			return phase
		}
	}
	return HAPhase{}
}
