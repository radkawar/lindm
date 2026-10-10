package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"golang.org/x/mod/semver"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/buildinfo"
	"lindm/internal/agent/journal"
	"lindm/internal/releaseupdate"
)

// Engine is constructor-bound to protected bootstrap material and local config.
// Its only cross-process input is a bounded answer to a pending fetch request.
type Engine struct {
	mu        sync.Mutex
	cfg       *agentv1.AgentUpdateConfig
	deviceID  string
	store     *journal.UpdateStore
	client    *releaseupdate.Client
	bridge    *bridge
	ctx       context.Context
	cancel    context.CancelFunc
	worker    sync.WaitGroup
	closed    bool
	running   bool
	next      time.Time
	status    *agentv1.AgentUpdateStatus
	validator protovalidate.Validator
}

func New(ctx context.Context, directory, deviceID string, root []byte, cfg *agentv1.AgentUpdateConfig) (_ *Engine, resultErr error) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&agentv1.AgentUpdateConfig{}, &agentv1.AgentUpdateHelperState{}), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, err
	}
	if err := validator.Validate(cfg); err != nil {
		return nil, err
	}
	store, err := journal.OpenUpdates(directory)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			_ = store.Close()
		}
	}()
	b := newBridge()
	client, err := releaseupdate.NewClient(releaseupdate.ClientConfig{StateDir: filepath.Join(store.Directory, "tuf"), BootstrapRoot: root, Fetch: b.fetch, Now: time.Now})
	if err != nil {
		return nil, err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	e := &Engine{cfg: proto.CloneOf(cfg), deviceID: deviceID, store: store, client: client, bridge: b, ctx: workerCtx, cancel: cancel, validator: validator}
	e.recordStatus(store.Load())
	return e, nil
}

func (e *Engine) Close() error {
	e.mu.Lock()
	e.closed = true
	e.cancel()
	e.mu.Unlock()
	e.worker.Wait()
	return e.store.Close()
}

func (e *Engine) Status() *agentv1.AgentUpdateStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := proto.CloneOf(e.status)
	if e.running && (status.GetPhase() == "idle" || status.GetPhase() == "installed" || status.GetPhase() == "rejected") {
		status.Phase = "checking"
	}
	// The native transaction may replace the executor and fail before its
	// network process reconnects. Surface only durable helper failures here;
	// status reads must neither launch recovery nor promote helper success
	// without recover's independent native package/payload checks.
	if !e.running && status.GetPhase() == "applying" && status.GetTransactionId() != "" {
		helper := &agentv1.AgentUpdateHelperState{}
		err := journal.ReadUpdateRecord(filepath.Join(e.store.Directory, status.GetTransactionId()), "helper.pb", helper)
		if err == nil {
			err = e.validator.Validate(helper)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			status.Phase, status.Reason, status.LastOutcome = "recovery_required", "update_helper_state_unavailable", "incomplete"
		} else if err == nil && (helper.GetPhase() == "recovery_required" || helper.GetPhase() == "rejected") {
			status.Phase, status.Reason, status.LastOutcome = helper.GetPhase(), "native_transaction_incomplete", "incomplete"
			if helper.GetPhase() == "rejected" {
				status.Reason, status.LastOutcome = "verified_transaction_expired", "rejected"
			}
			status.ObservedAt = helper.GetObservedAt()
			if helper.GetNativeDiagnostic() != nil {
				status.NativeDiagnostic = helper.GetNativeDiagnostic()
			}
		}
	}
	return status
}

// Busy includes unknown interrupted transactions: destructive actions cannot
// invalidate the staged recovery executable or native transaction journal.
func (e *Engine) Busy() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running || e.status.GetPhase() == "staged" || e.status.GetPhase() == "applying" || e.status.GetPhase() == "installing" || e.status.GetPhase() == "recovery_required"
}

// Begin reserves update admission while the caller holds its executor authority
// lock. Network waits happen later, outside that lock.
func (e *Engine) Begin() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("update engine closed")
	}
	if !e.running && !time.Now().Before(e.next) {
		e.running = true
		e.worker.Add(1)
		go e.run()
	}
	return nil
}

func (e *Engine) Exchange(ctx context.Context, request *agentv1.ExchangeAgentUpdateRequest) (*agentv1.ExchangeAgentUpdateResponse, error) {
	fetch, err := e.bridge.exchange(ctx, request)
	if err != nil {
		return nil, err
	}
	return &agentv1.ExchangeAgentUpdateResponse{RepositoryUrl: e.cfg.GetRepositoryUrl(), Fetch: fetch, Status: e.Status(), PollIntervalSeconds: e.cfg.GetPollIntervalSeconds()}, nil
}

func (e *Engine) recordStatus(state *agentv1.AgentUpdateJournal) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status = &agentv1.AgentUpdateStatus{Enabled: true, Phase: state.GetPhase(), Version: state.GetInstalledVersion(), Reason: state.GetReason(), ObservedAt: state.GetObservedAt(), AttemptStartedAt: state.GetAttemptStartedAt(), AttemptFinishedAt: state.GetAttemptFinishedAt(), LastOutcome: state.GetLastOutcome(), LastMetadataAt: state.GetLastMetadataAt(), NativeDiagnostic: proto.CloneOf(state.GetNativeDiagnostic())}
	if tx := state.GetTransaction(); tx != nil {
		e.status.TransactionId = tx.GetId()
		e.status.Version = tx.GetVersion()
	}
}

func (e *Engine) save(state *agentv1.AgentUpdateJournal) error {
	state.ObservedAt = timestamppb.Now()
	if err := e.store.Save(state); err != nil {
		return err
	}
	e.recordStatus(state)
	return nil
}

func (e *Engine) run() {
	defer e.worker.Done()
	ctx, cancel := context.WithTimeout(e.ctx, 15*time.Minute)
	defer cancel()
	state := e.store.Load()
	state.AttemptStartedAt, state.AttemptFinishedAt, state.LastOutcome = timestamppb.Now(), nil, "checking"
	err := e.save(state)
	if err == nil {
		err = e.cycle(ctx)
	}
	state = e.store.Load()
	state.AttemptFinishedAt = timestamppb.Now()
	if err != nil {
		if diagnostic := diagnosticForError(err); diagnostic != nil {
			state.NativeDiagnostic = diagnostic
		}
		state.LastOutcome, state.Reason = "rejected", "update_rejected_or_incomplete"
		if state.GetPhase() == "applying" || state.GetPhase() == "recovery_required" {
			state.LastOutcome = "incomplete"
		}
	}
	saveErr := e.save(state)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.running = false
	e.next = time.Now().Add(time.Duration(e.cfg.GetPollIntervalSeconds()) * time.Second)
	if saveErr != nil {
		e.status.Phase, e.status.Reason, e.status.LastOutcome = "recovery_required", "update_checkpoint_failed", "incomplete"
	}
}

func (e *Engine) cycle(ctx context.Context) error {
	state := e.store.Load()
	if tx := state.GetTransaction(); tx != nil && state.GetPhase() != "installed" && state.GetPhase() != "rejected" {
		return e.recover(ctx, state)
	}
	if err := e.reclaimRetired(ctx, state); err != nil {
		return err
	}
	if err := mutablePlatform(e.cfg.GetManager()); err != nil {
		return err
	}
	current := buildinfo.Current().Version
	if !semver.IsValid("v"+current) || (state.GetInstalledVersion() != "" && semver.Compare("v"+current, "v"+state.GetInstalledVersion()) < 0) {
		return errors.New("running agent is unstamped or downgraded")
	}
	installed, err := observeInstalled(ctx, e.cfg.GetManager(), "validation")
	if err != nil {
		return err
	}
	if err := installed.matchesRunning(current, runtime.GOARCH); err != nil {
		return err
	}
	state.InstalledVersion = current
	if err := e.save(state); err != nil {
		return err
	}
	e.mu.Lock()
	e.status.Phase = "checking"
	e.status.Reason = ""
	e.mu.Unlock()
	selection, err := e.client.Select(ctx, releaseupdate.SelectionRequest{Ring: e.cfg.GetRing(), DeviceID: e.deviceID, CurrentVersion: current, Architecture: runtime.GOARCH, PackageFormat: packageFormat(e.cfg.GetManager()), ProtocolVersion: buildinfo.ProtocolVersion})
	if err == nil || errors.Is(err, releaseupdate.ErrNoUpdate) {
		state.LastMetadataAt = timestamppb.Now()
		state.LastOutcome = "no_update"
		if saveErr := e.save(state); saveErr != nil {
			return saveErr
		}
	}
	if errors.Is(err, releaseupdate.ErrNoUpdate) {
		return nil
	}
	if err != nil {
		return err
	}
	if selection.Length <= 0 || selection.Length > 1<<30 {
		return errors.New("update package exceeds staging bound")
	}
	tx := &agentv1.AgentUpdateTransaction{Id: uuid.NewString(), Version: selection.Artifact.GetVersion(), NativeVersion: selection.Artifact.GetNativeVersion(), PreviousNativeVersion: installed.version, PreviousVersion: current, Manager: e.cfg.GetManager(), Architecture: runtime.GOARCH, Sha256: selection.SHA256, Length: uint64(selection.Length), AdmittedAt: timestamppb.Now(), VerifiedExpiresAt: timestamppb.New(selection.Deadline())}
	directory := filepath.Join(e.store.Directory, tx.GetId())
	if err := os.Mkdir(directory, 0700); err != nil {
		return err
	}
	admitted := false
	defer func() {
		if !admitted {
			_ = os.RemoveAll(directory)
		}
	}()
	// Derive the native filename only from validated package identity, never
	// from a network pathname. APT requires its canonical private cache name.
	downloadCtx, stopDownload := context.WithDeadline(ctx, selection.Deadline())
	err = e.client.Stage(downloadCtx, selection, &remoteReader{ctx: downloadCtx, bridge: e.bridge, path: selection.TargetPath}, packagePath(directory, tx))
	if err == nil && selection.SignaturePath != "" {
		err = e.client.StageSignature(downloadCtx, selection, &remoteReader{ctx: downloadCtx, bridge: e.bridge, path: selection.SignaturePath}, packagePath(directory, tx)+".sig")
	}
	stopDownload()
	if err != nil {
		return err
	}
	if err := validatePackage(ctx, directory, tx); err != nil {
		return err
	}
	if err := preserveHelper(directory); err != nil {
		return err
	}
	if err := journal.WriteUpdateRecord(directory, "transaction.pb", tx); err != nil {
		return err
	}
	state.Transaction, state.Phase, state.Reason = tx, "staged", ""
	// Admission write failure is ambiguous after rename; retain recovery bytes.
	admitted = true
	if err := e.save(state); err != nil {
		return err
	}
	if err := e.reclaimRetired(ctx, state); err != nil {
		return err
	}
	// Save before contacting systemd. Ambiguous launch is recovered using the
	// deterministic unit identity and exact package database state.
	state.Phase = "applying"
	if err := e.save(state); err != nil {
		return err
	}
	if err := launchHelper(ctx, directory, tx); err != nil {
		return err
	}
	return e.recover(ctx, state)
}

func (e *Engine) recover(ctx context.Context, state *agentv1.AgentUpdateJournal) error {
	tx := state.GetTransaction()
	directory := filepath.Join(e.store.Directory, tx.GetId())
	for {
		help := &agentv1.AgentUpdateHelperState{}
		err := journal.ReadUpdateRecord(directory, "helper.pb", help)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil {
			if err := e.validator.Validate(help); err != nil {
				return err
			}
			if err := e.recordHelperState(state, help); err != nil {
				return err
			}
		}
		active, err := helperActive(ctx, tx)
		if err != nil {
			return err
		}
		if !active {
			if help.GetPhase() == "rejected" {
				state.Phase, state.Reason, state.LastOutcome = "rejected", "verified_transaction_expired", "rejected"
				return e.save(state)
			}
			installed, observedErr := observeInstalled(ctx, tx.GetManager(), "recovery")
			if observedErr == nil && installed.matchesTransaction(tx) == nil && help.GetPhase() == "installed" {
				if err := verifyInstalledPayload(ctx, tx); err != nil {
					return err
				}
				state.InstalledVersion, state.Phase, state.Reason = tx.GetVersion(), "installed", ""
				state.LastOutcome = "installed"
				state.NativeDiagnostic = nil
				return e.save(state)
			}
			// A durable staged transaction may precede any helper launch, or the
			// host may have rebooted after unit cleanup. The helper independently
			// re-observes native state before repairing ONLY this agent package.
			if help.GetPhase() != "recovery_required" {
				if err := launchHelper(ctx, directory, tx); err != nil {
					return err
				}
			} else {
				state.Phase, state.Reason = "recovery_required", "native_transaction_incomplete"
				if err := e.save(state); err != nil {
					return err
				}
				return fmt.Errorf("agent update %s requires native recovery", tx.GetId())
			}
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (e *Engine) recordHelperState(state *agentv1.AgentUpdateJournal, help *agentv1.AgentUpdateHelperState) error {
	// The helper's installed marker is not sufficient proof of replacement.
	// Preserve historical failure until recover verifies native state and payload.
	diagnostic := state.GetNativeDiagnostic()
	if help.GetNativeDiagnostic() != nil {
		diagnostic = help.GetNativeDiagnostic()
	}
	phase := help.GetPhase()
	if phase == "installing" {
		phase = "applying"
	}
	if phase == "installed" {
		phase = state.GetPhase()
	}
	if state.GetPhase() == phase && proto.Equal(state.GetNativeDiagnostic(), diagnostic) {
		return nil
	}
	state.Phase, state.NativeDiagnostic = phase, proto.CloneOf(diagnostic)
	return e.save(state)
}
