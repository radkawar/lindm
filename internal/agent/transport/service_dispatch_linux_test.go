//go:build linux

package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/gen/lindm/device/v1/devicev1connect"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestServiceDispatchNoDrift(t *testing.T) {
	f := newDispatchFixture(t)
	f.state = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
	if err := f.loop.dispatchServices(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.starts != 0 || f.authorizations != 0 || f.polls != 0 || f.reports != 1 || !f.closed {
		t.Fatalf("no-drift action took an execution path: %v", f.events)
	}
	if bytes.Equal(f.attestedNonce, f.initialNonce) {
		t.Fatal("reported with the nonce fetched before preparation")
	}
}

// Sealed deliveries are opaque to the relay: the executor must receive the
// server's exact ciphertext, in order, or the signed digests cannot match.
func TestServiceDispatchRelaysExactSealedSecrets(t *testing.T) {
	f := newDispatchFixture(t)
	f.state = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
	f.work.SealedSecrets = [][]byte{[]byte(" first sealed\n"), []byte(" second sealed\n")}
	if err := f.loop.dispatchServices(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(f.preparedSecrets) != 2 || !bytes.Equal(f.preparedSecrets[0], []byte(" first sealed\n")) || !bytes.Equal(f.preparedSecrets[1], []byte(" second sealed\n")) {
		t.Fatal("relay changed, reordered or dropped sealed deliveries")
	}
}

func TestResourceReadOnlyOutcomesNeverRequestEffectAuthority(t *testing.T) {
	for _, disposition := range []resourcev1.VerificationDisposition{
		resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED,
		resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN,
		resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE,
	} {
		t.Run(disposition.String(), func(t *testing.T) {
			f := newDispatchFixture(t)
			f.readOnlyDisposition = disposition
			f.state = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED
			if disposition == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE {
				f.state = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
			}
			if err := f.loop.dispatchServices(t.Context()); err != nil {
				t.Fatal(err)
			}
			if f.starts != 0 || f.authorizations != 0 || f.polls != 0 || f.reports != 1 || !f.closed || f.attestedState != f.state {
				t.Fatalf("read-only native outcome entered an effect path or lost history: %v", f.events)
			}
		})
	}
}

func TestServicePreparationSpansManagementCyclesWithoutGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDispatchFixture(t)
		f.state = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING
		// Independent native staging becomes READY between management cycles.
		// Only the later fourth Prepare can return a fresh exact challenge.
		f.readyAtPrepare = 4
		f.readyPollStates = []agentv1.ResourceExecutionState{agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED}
		begin := time.Now()
		stop := f.loop.start(t.Context())
		time.Sleep(3 * managementInterval)
		synctest.Wait()
		// Stopping joins the relay goroutine before its fixture state is read.
		stop()
		if len(f.prepareSnapshots) != 4 {
			t.Fatalf("staging blocked ordinary management cycles: %d prepares", len(f.prepareSnapshots))
		}
		for i, seen := range f.prepareSnapshots {
			cycle := i + 1
			// Each Prepare begins a cycle after every earlier cycle reported.
			if seen.reports != cycle-1 || seen.devicePolls < cycle-1 {
				t.Fatalf("staging blocked ordinary management cycles: cycle=%d %+v", cycle, seen)
			}
			if seen.polls != 0 || seen.authorizations != 0 || seen.starts != 0 || seen.closed || seen.evidence {
				t.Fatalf("pending staging acquired authority, evidence or busy polling: cycle=%d %+v", cycle, seen)
			}
			if elapsed := seen.at.Sub(begin); elapsed != time.Duration(i)*managementInterval {
				t.Fatalf("staging stretched the management cadence: %v", elapsed)
			}
		}
		if f.authorizations != 1 || f.starts != 1 || !f.closed || f.reports != 4 || !f.startAt.Equal(f.challengeAt) {
			t.Fatalf("ready plan did not immediately relay its exact fresh authority: %v", f.events)
		}
	})
}

func TestServicePreparationCancellationReportsOwnedTerminalHistory(t *testing.T) {
	for _, state := range []agentv1.ResourceExecutionState{
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED,
	} {
		for _, duringPrepare := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/during-prepare=%t", state, duringPrepare), func(t *testing.T) {
				f := newDispatchFixture(t)
				f.state = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING
				f.cancelState = state
				if duringPrepare {
					f.changeWorkOnRefresh = "cancel-preparation"
				} else {
					f.work.CancelPreparation = true
				}
				if err := f.loop.dispatchServices(t.Context()); err != nil {
					t.Fatal(err)
				}
				if f.cancels != 1 || f.starts != 0 || f.authorizations != 0 || !f.closed || f.attestedState != state || f.reports != 1 {
					t.Fatalf("pending cancellation lost terminal owned cleanup: %v", f.events)
				}
				if !duringPrepare && f.prepares != 0 {
					t.Fatal("cancelled work restarted preparation")
				}
			})
		}
	}
}

func TestServicePreparationRPCDeadlineUnchanged(t *testing.T) {
	for _, phase := range []string{"prepare", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDispatchFixture(t)
				f.state = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING
				f.blockPhase = phase
				f.work.CancelPreparation = phase == "cancel"
				begin := time.Now()
				digest := sha256.Sum256(f.intent)
				var err error
				if phase == "cancel" {
					_, err = f.loop.cancelResourcePreparation(t.Context(), f.work, digest)
				} else {
					_, err = f.loop.prepareAndStartService(t.Context(), f.work, digest)
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("blocked preparation call: %v", err)
				}
				if time.Since(begin) != 15*time.Second {
					t.Fatal("preparation stretched the ordinary RPC deadline")
				}
			})
		})
	}
}

func TestServicePreparationNeverAcceptedAcknowledgesNoNativeProof(t *testing.T) {
	f := newDispatchFixture(t)
	f.work.CancelPreparation = true
	f.neverPrepared = true
	if err := f.loop.dispatchServices(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !f.closed || f.cancels != 1 || f.reports != 1 || f.attestations != 0 || f.prepares != 0 || f.starts != 0 {
		t.Fatalf("never-prepared cancellation fabricated native evidence or restarted staging: %v", f.events)
	}
}

func TestServiceDispatchLostStartAuthorizationReplaysStoredGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDispatchFixture(t)
		f.loseAuthorization = true
		f.pollStates = []agentv1.ResourceExecutionState{
			agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING,
			agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED,
		}
		if err := f.loop.dispatchServices(t.Context()); err != nil {
			t.Fatal(err)
		}
		if f.authorizations != 1 || f.starts != 0 || f.closed || f.reports != 1 {
			t.Fatalf("lost response was mistaken for accepted execution: %v", f.events)
		}
		// The next management cycle receives the exact already-issued grant.
		// It must not reauthorize or replace the protected challenge.
		time.Sleep(managementInterval)
		if err := f.loop.dispatchServices(t.Context()); err != nil {
			t.Fatal(err)
		}
		if f.authorizations != 1 || f.starts != 1 || !f.closed || f.reports != 2 {
			t.Fatalf("stored grant was not recovered exactly once: %v", f.events)
		}
		if f.attestedState != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED {
			t.Fatal("queue acceptance was reported as terminal completion")
		}
	})
}

func TestServiceDispatchPollsToTerminalWithFreshSessionAndNonce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDispatchFixture(t)
		f.pollStates = []agentv1.ResourceExecutionState{
			agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING,
			agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED,
		}
		f.changeSessionOnTerminal = true
		if err := f.loop.dispatchServices(t.Context()); err != nil {
			t.Fatal(err)
		}
		if f.starts != 1 || f.polls != 2 || f.attestedState != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED || f.attestedEpoch != 2 {
			t.Fatalf("terminal result/session was not refreshed: %v", f.events)
		}
		if bytes.Equal(f.attestedNonce, f.initialNonce) || !bytes.Equal(f.attestedNonce, f.lastNonce) {
			t.Fatal("attestation did not use the fresh post-poll nonce")
		}
		if f.startAt.Sub(f.challengeAt) != 0 {
			t.Fatal("relay inserted a scheduling delay into challenge/start exchange")
		}
	})
}

func TestServiceDispatchReportsExistingAndExpiredHistory(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state agentv1.ResourceExecutionState
		code  connect.Code
	}{
		{"already-running", agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING, 0},
		{"already-succeeded", agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, 0},
		{"already-failed", agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, 0},
		{"already-unknown", agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN, 0},
		{"already-expired", agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED, 0},
		{"already-superseded", agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED, 0},
		{"prepare-conflict", agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, connect.CodeAlreadyExists},
		{"prepare-expired", agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED, connect.CodeFailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDispatchFixture(t)
			f.state = tc.state
			if tc.code != 0 {
				f.prepareErr = connect.NewError(tc.code, errors.New(tc.name))
			}
			if tc.state == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
				f.pollStates = []agentv1.ResourceExecutionState{agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED}
			}
			if err := f.loop.dispatchServices(t.Context()); err != nil {
				t.Fatal(err)
			}
			if f.starts != 0 || f.authorizations != 0 || f.reports != 1 || !f.closed {
				t.Fatalf("existing history was executed again or not reported: %v", f.events)
			}
		})
	}
}

func TestServiceDispatchExpiredStartReportsHistory(t *testing.T) {
	f := newDispatchFixture(t)
	f.work.StartGrantEnvelope = f.grant
	f.startErr = connect.NewError(connect.CodeFailedPrecondition, errors.New("service_execution_expired"))
	if err := f.loop.dispatchServices(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.authorizations != 0 || f.starts != 1 || f.reports != 1 || f.attestedState != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED {
		t.Fatalf("expired exact grant did not report protected history: %v", f.events)
	}
}

func TestServiceDispatchPollingBoundDoesNotInventCompletion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDispatchFixture(t)
		begin := time.Now()
		if err := f.loop.dispatchServices(t.Context()); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(begin); elapsed != servicePollTimeout {
			t.Fatalf("poll duration = %v, want %v", elapsed, servicePollTimeout)
		}
		if f.closed || f.reports != 1 || f.attestedState != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED {
			t.Fatalf("bounded polling invented terminal success: %v", f.events)
		}
		if f.polls > 1+int(servicePollTimeout/servicePollInterval) {
			t.Fatal("local polling was not paced")
		}
	})
}

func TestServiceDispatchStopsWhenFreshWorkChanges(t *testing.T) {
	for _, change := range []string{"cleared", "different-action", "different-intent"} {
		t.Run(change, func(t *testing.T) {
			f := newDispatchFixture(t)
			f.state = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
			f.changeWorkOnRefresh = change
			err := f.loop.dispatchServices(t.Context())
			if (err != nil) != (change == "different-intent") {
				t.Fatalf("changed work error = %v", err)
			}
			if f.attestations != 0 || f.reports != 0 || f.prepares != 1 {
				t.Fatalf("reported or executed work after nonce action changed: %v", f.events)
			}
		})
	}
}

func TestServiceDispatchBoundsActionsPerCycle(t *testing.T) {
	f := newDispatchFixture(t)
	f.state = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
	f.moreActions = true
	if err := f.loop.dispatchServices(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.reports != serviceActionsPerCycle || f.prepares != serviceActionsPerCycle {
		t.Fatalf("cycle did not bound action processing: reports=%d prepares=%d", f.reports, f.prepares)
	}
}

func TestServiceDispatchRejectsUnboundHistory(t *testing.T) {
	for _, field := range []string{"action", "intent"} {
		t.Run(field, func(t *testing.T) {
			f := newDispatchFixture(t)
			f.badStatus = field
			if err := f.loop.dispatchServices(t.Context()); err == nil {
				t.Fatal("accepted history for another action/intent")
			}
			if f.starts != 0 || f.authorizations != 0 || f.reports != 0 {
				t.Fatalf("unbound status escaped the relay: %v", f.events)
			}
		})
	}
}

func TestManagementCancellationJoinsEveryPhase(t *testing.T) {
	for _, phase := range []string{"trust", "work", "prepare", "authorize", "start", "poll", "attest", "report"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDispatchFixture(t)
				f.blockPhase = phase
				f.pollStates = []agentv1.ResourceExecutionState{agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED}
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				stop := f.loop.start(ctx)
				defer stop()
				select {
				case <-f.entered:
				case <-ctx.Done():
					t.Fatalf("management never reached %s", phase)
				}
				stop()
				select {
				case <-f.exited:
				default:
					t.Fatal("management stop returned before its in-flight phase exited")
				}
				if f.loop.cache.servers != nil {
					t.Fatal("management stop did not join connection cleanup")
				}
			})
		})
	}
}

func TestManagementTrustDispatchCadenceAndIdleJoin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDispatchFixture(t)
		f.work = nil
		begin := time.Now()
		stop := f.loop.start(t.Context())
		defer stop()
		synctest.Wait()
		time.Sleep(managementInterval)
		synctest.Wait()
		stop()
		if !slices.Equal(f.events, []string{"trust", "work", "trust", "work"}) {
			t.Fatalf("empty dispatch did not use management cadence: %v", f.events)
		}
		if !f.phaseTimes[0].Equal(begin) || !f.phaseTimes[1].Equal(begin) || !f.phaseTimes[2].Equal(begin.Add(managementInterval)) || !f.phaseTimes[3].Equal(begin.Add(managementInterval)) {
			t.Fatalf("trust/dispatch phases were delayed or incorrectly paced: %v", f.phaseTimes)
		}
	})
}

func TestServiceDispatchRPCDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDispatchFixture(t)
		f.blockPhase = "work"
		begin := time.Now()
		if err := f.loop.dispatchServices(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked remote call: %v", err)
		}
		if time.Since(begin) != requestTimeout {
			t.Fatal("remote call exceeded the shared RPC deadline")
		}
	})
}

// These stateful boundaries model the server-owned open action and executor
// consumption/history. They do not claim cryptographic or native-effect proof.
// Opaque envelopes deliberately contain whitespace so byte rewriting is caught.
// prepareSnapshot is recorded by the relay goroutine itself at each Prepare.
type prepareSnapshot struct {
	at                                                  time.Time
	reports, devicePolls, polls, authorizations, starts int
	closed, evidence                                    bool
}

type dispatchFixture struct {
	t          *testing.T
	loop       *managementLoop
	work       *devicev1.ResourceWork
	state      agentv1.ResourceExecutionState
	pollStates []agentv1.ResourceExecutionState
	// readyAtPrepare makes independent staging READY on that Prepare call, in
	// the relay goroutine, so the test never writes state the loop reads.
	readyAtPrepare           int
	readyPollStates          []agentv1.ResourceExecutionState
	prepareSnapshots         []prepareSnapshot
	preparedSecrets          [][]byte
	intent, challenge, grant []byte
	attestation, certificate []byte
	initialNonce, lastNonce  []byte
	attestedNonce            []byte
	attestedState            agentv1.ResourceExecutionState
	epoch, attestedEpoch     uint64
	connection               *agentv1.GetConnectionResponse
	events                   []string
	prepares, starts, polls  int
	cancels, devicePolls     int
	cancelState              agentv1.ResourceExecutionState
	neverPrepared            bool
	readOnlyDisposition      resourcev1.VerificationDisposition
	authorizations, reports  int
	attestations, workCalls  int
	establishments           int
	lastRemoteEstablishment  int
	closed, moreActions      bool
	loseAuthorization        bool
	changeSessionOnTerminal  bool
	changeWorkOnRefresh      string
	badStatus                string
	prepareErr, startErr     error
	challengeAt, startAt     time.Time
	phaseTimes               []time.Time
	blockPhase               string
	entered, exited          chan struct{}
}

func newDispatchFixture(t *testing.T) *dispatchFixture {
	t.Helper()
	f := &dispatchFixture{
		t: t, epoch: 1, state: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED,
		intent: []byte(" exact intent\n"), challenge: []byte(" exact challenge\n"), grant: []byte(" exact grant\n"),
		attestation: []byte(" exact attestation\n"), certificate: []byte(" exact certificate\n"),
		entered: make(chan struct{}), exited: make(chan struct{}),
	}
	f.work = &devicev1.ResourceWork{ActionId: "11111111-1111-4111-8111-111111111111", IntentEnvelope: f.intent}
	f.connection = &agentv1.GetConnectionResponse{SessionEpoch: 1, SessionEpochUsable: true, RenewAfter: timestamppb.New(time.Now().Add(time.Hour))}
	f.loop = &managementLoop{
		executor: &dispatchExecutor{f: f}, gate: make(authorityGate, 1),
		cache: connectionCache{connection: proto.CloneOf(f.connection), servers: &connections{device: &dispatchServer{f: f}}},
	}
	return f
}

func (f *dispatchFixture) phase(ctx context.Context, phase string) error {
	f.events = append(f.events, phase)
	f.phaseTimes = append(f.phaseTimes, time.Now())
	if phase != f.blockPhase {
		return ctx.Err()
	}
	close(f.entered)
	<-ctx.Done()
	close(f.exited)
	return ctx.Err()
}

func (f *dispatchFixture) remote(epoch uint64) {
	f.t.Helper()
	if epoch != f.epoch || f.establishments <= f.lastRemoteEstablishment {
		f.t.Fatalf("remote phase reused stale authority: epoch=%d current=%d establishments=%d previous=%d", epoch, f.epoch, f.establishments, f.lastRemoteEstablishment)
	}
	f.lastRemoteEstablishment = f.establishments
}

func (f *dispatchFixture) status() *agentv1.ResourceExecutionStatus {
	digest := sha256.Sum256(f.intent)
	native := &resourcev1.SystemdServiceObservation{
		Unit: "fixture.service", BootId: "22222222-2222-4222-8222-222222222222", ObservedAt: timestamppb.Now(),
		LoadState: "loaded", DefinitionSha256: digest[:], FingerprintSha256: digest[:],
	}
	observation := &resourcev1.ResourceObservation{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: native.GetUnit()},
		Metadata: &resourcev1.ObservationMetadata{
			BootId: native.GetBootId(), ExecutorIncarnation: "a2bca405-36e9-4a43-b5b5-d0b82a05e551", ObservedAt: proto.CloneOf(native.GetObservedAt()),
			Backend:        &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_SYSTEMD, NativeVersion: "255", ProviderVersion: "1", Product: &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "x86_64"}},
			NativeRevision: digest[:], ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK,
		},
		Observed: &resourcev1.ResourceObservation_SystemdService{SystemdService: native},
	}
	status := &agentv1.ResourceExecutionStatus{
		ActionId: f.work.GetActionId(), IntentSha256: digest[:], State: f.state,
		Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE, AcceptedAt: timestamppb.Now(), Before: observation,
	}
	if f.state == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED {
		if f.starts == 0 {
			status.ReadOnly = true
		} else {
			status.StartedAt = timestamppb.Now()
		}
	}
	if f.state == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
		status.Before = nil
	}
	if f.state == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
		status.StartedAt = timestamppb.Now()
	}
	if serviceExecutionTerminal(f.state) {
		status.CompletedAt = timestamppb.Now()
		if f.state == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED {
			status.Verification = &resourcev1.ResourceVerification{
				Ref: proto.CloneOf(observation.GetRef()), DesiredSha256: digest[:], PlanSha256: digest[:],
				After: observation, Disposition: resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED,
				Checks: &resourcev1.ResourceVerification_SystemdService{SystemdService: &resourcev1.SystemdServiceChecks{Observation: native, RuntimeMatches: true, EnablementMatches: true, DefinitionMatches: true, Converged: true, JobCompleted: true}},
			}
		} else {
			status.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED
		}
	}
	if f.readOnlyDisposition != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNSPECIFIED {
		status.ReadOnly = true
		status.Verification = &resourcev1.ResourceVerification{
			Ref: proto.CloneOf(observation.GetRef()), DesiredSha256: digest[:], PlanSha256: digest[:],
			After: observation, Disposition: f.readOnlyDisposition,
			Checks: &resourcev1.ResourceVerification_SystemdService{SystemdService: &resourcev1.SystemdServiceChecks{Observation: native}},
		}
		if f.state == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED {
			status.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_POSTCONDITION
		}
	}
	if f.cancels != 0 {
		status.Before = nil
		status.PreparationOutcome = &agentv1.ResourcePreparationOutcome{
			Preparation: &agentv1.ResourceExecutionPreparation{Deadline: timestamppb.New(time.Now().Add(time.Minute)), MaxCacheBytes: 512 << 20},
			Failure:     status.GetFailure(),
		}
	}
	switch f.badStatus {
	case "action":
		status.ActionId = "33333333-3333-4333-8333-333333333333"
	case "intent":
		status.IntentSha256 = make([]byte, sha256.Size)
	}
	return status
}

type dispatchExecutor struct {
	agentv1connect.ExecutorServiceClient
	f *dispatchFixture
}

func (e *dispatchExecutor) GetConnection(context.Context, *connect.Request[agentv1.GetConnectionRequest]) (*connect.Response[agentv1.GetConnectionResponse], error) {
	e.f.establishments++
	connection := proto.CloneOf(e.f.connection)
	connection.SessionEpoch = e.f.epoch
	return connect.NewResponse(connection), nil
}

func (e *dispatchExecutor) PrepareSession(context.Context, *connect.Request[agentv1.PrepareSessionRequest]) (*connect.Response[agentv1.PrepareSessionResponse], error) {
	return connect.NewResponse(&agentv1.PrepareSessionResponse{Result: &agentv1.PrepareSessionResponse_Accepted{Accepted: &agentv1.AcceptedSession{SessionEpoch: e.f.epoch}}}), nil
}

func (*dispatchExecutor) GetExecutionTrust(context.Context, *connect.Request[agentv1.GetExecutionTrustRequest]) (*connect.Response[agentv1.GetExecutionTrustResponse], error) {
	return connect.NewResponse(&agentv1.GetExecutionTrustResponse{
		RootVersion: 1, RootSha256: make([]byte, sha256.Size), RootExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}), nil
}

func (e *dispatchExecutor) PrepareResourceExecution(ctx context.Context, req *connect.Request[agentv1.PrepareResourceExecutionRequest]) (*connect.Response[agentv1.PrepareResourceExecutionResponse], error) {
	f := e.f
	f.prepares++
	f.prepareSnapshots = append(f.prepareSnapshots, prepareSnapshot{at: time.Now(), reports: f.reports, devicePolls: f.devicePolls, polls: f.polls, authorizations: f.authorizations, starts: f.starts, closed: f.closed, evidence: f.status().GetBefore() != nil})
	if f.readyAtPrepare != 0 && f.prepares == f.readyAtPrepare {
		f.state, f.pollStates = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED, f.readyPollStates
	}
	f.preparedSecrets = req.Msg.GetSealedSecrets()
	if !bytes.Equal(req.Msg.GetIntentEnvelope(), f.intent) {
		f.t.Fatal("executor did not receive the exact server intent")
	}
	if err := f.phase(ctx, "prepare"); err != nil {
		return nil, err
	}
	if f.prepareErr != nil {
		return nil, f.prepareErr
	}
	var challenge []byte
	if f.state == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED {
		f.challengeAt = time.Now()
		challenge = f.challenge
	}
	return connect.NewResponse(&agentv1.PrepareResourceExecutionResponse{Status: f.status(), ChallengeProof: challenge}), nil
}

func (e *dispatchExecutor) StartResourceExecution(ctx context.Context, req *connect.Request[agentv1.StartResourceExecutionRequest]) (*connect.Response[agentv1.StartResourceExecutionResponse], error) {
	f := e.f
	f.starts++
	f.startAt = time.Now()
	if req.Msg.GetActionId() != f.work.GetActionId() || !bytes.Equal(req.Msg.GetStartGrantEnvelope(), f.grant) {
		f.t.Fatal("executor did not receive the exact server grant/action")
	}
	if err := f.phase(ctx, "start"); err != nil {
		return nil, err
	}
	if f.state != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED {
		f.t.Fatal("relay attempted to replay an already consumed effect")
	}
	if f.startErr != nil {
		f.state = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
		return nil, f.startErr
	}
	f.state = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED
	return connect.NewResponse(&agentv1.StartResourceExecutionResponse{Status: f.status()}), nil
}

func (e *dispatchExecutor) GetResourceExecution(ctx context.Context, req *connect.Request[agentv1.GetResourceExecutionRequest]) (*connect.Response[agentv1.GetResourceExecutionResponse], error) {
	f := e.f
	f.polls++
	if req.Msg.GetActionId() != f.work.GetActionId() {
		f.t.Fatal("relay invented a history action ID")
	}
	if err := f.phase(ctx, "poll"); err != nil {
		return nil, err
	}
	if f.state != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED && len(f.pollStates) != 0 {
		f.state, f.pollStates = f.pollStates[0], f.pollStates[1:]
		if serviceExecutionTerminal(f.state) && f.changeSessionOnTerminal {
			f.epoch++
		}
	}
	return connect.NewResponse(&agentv1.GetResourceExecutionResponse{Status: f.status()}), nil
}

func (e *dispatchExecutor) CancelResourcePreparation(ctx context.Context, req *connect.Request[agentv1.CancelResourcePreparationRequest]) (*connect.Response[agentv1.CancelResourcePreparationResponse], error) {
	f := e.f
	digest := sha256.Sum256(f.intent)
	if req.Msg.GetActionId() != f.work.GetActionId() || !bytes.Equal(req.Msg.GetIntentSha256(), digest[:]) {
		f.t.Fatal("cancellation did not bind the exact owned intent")
	}
	if err := f.phase(ctx, "cancel"); err != nil {
		return nil, err
	}
	f.cancels++
	if f.neverPrepared {
		return connect.NewResponse(&agentv1.CancelResourcePreparationResponse{NeverPrepared: true}), nil
	}
	f.state = f.cancelState
	return connect.NewResponse(&agentv1.CancelResourcePreparationResponse{Status: f.status()}), nil
}

func (e *dispatchExecutor) AttestResourceExecution(ctx context.Context, req *connect.Request[agentv1.AttestResourceExecutionRequest]) (*connect.Response[agentv1.AttestResourceExecutionResponse], error) {
	f := e.f
	f.attestations++
	if req.Msg.GetActionId() != f.work.GetActionId() || !bytes.Equal(req.Msg.GetNonce(), f.lastNonce) || bytes.Equal(req.Msg.GetNonce(), f.initialNonce) {
		f.t.Fatal("attestation did not bind the same action and fresh nonce")
	}
	if err := f.phase(ctx, "attest"); err != nil {
		return nil, err
	}
	f.attestedNonce = bytes.Clone(req.Msg.GetNonce())
	f.attestedEpoch, f.attestedState = f.epoch, f.state
	return connect.NewResponse(&agentv1.AttestResourceExecutionResponse{AttestationEnvelope: f.attestation, CertificatePem: f.certificate}), nil
}

type dispatchServer struct {
	devicev1connect.DeviceServiceClient
	f *dispatchFixture
}

func (s *dispatchServer) GetExecutionTrust(ctx context.Context, req *connect.Request[devicev1.GetExecutionTrustRequest]) (*connect.Response[devicev1.GetExecutionTrustResponse], error) {
	s.f.remote(req.Msg.GetSessionEpoch())
	if err := s.f.phase(ctx, "trust"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&devicev1.GetExecutionTrustResponse{}), nil
}

// Service-loop fixtures have no imperative device actions.
func (s *dispatchServer) GetDeviceActionWork(context.Context, *connect.Request[devicev1.GetDeviceActionWorkRequest]) (*connect.Response[devicev1.GetDeviceActionWorkResponse], error) {
	s.f.devicePolls++
	return connect.NewResponse(&devicev1.GetDeviceActionWorkResponse{}), nil
}

func (s *dispatchServer) GetResourceWork(ctx context.Context, req *connect.Request[devicev1.GetResourceWorkRequest]) (*connect.Response[devicev1.GetResourceWorkResponse], error) {
	f := s.f
	f.remote(req.Msg.GetSessionEpoch())
	f.workCalls++
	if err := f.phase(ctx, "work"); err != nil {
		return nil, err
	}
	if f.work == nil || f.closed {
		return connect.NewResponse(&devicev1.GetResourceWorkResponse{}), nil
	}
	work := proto.CloneOf(f.work)
	if f.workCalls == 2 {
		switch f.changeWorkOnRefresh {
		case "cleared":
			return connect.NewResponse(&devicev1.GetResourceWorkResponse{}), nil
		case "different-action":
			work.ActionId = "33333333-3333-4333-8333-333333333333"
		case "different-intent":
			work.IntentEnvelope = []byte("changed intent")
		case "cancel-preparation":
			work.CancelPreparation = true
		}
	}
	work.ResultNonce = make([]byte, 32)
	work.ResultNonce[0] = byte(f.workCalls)
	work.ResultNonceExpiresAt = timestamppb.New(time.Now().Add(time.Minute))
	f.lastNonce = bytes.Clone(work.ResultNonce)
	if f.initialNonce == nil {
		f.initialNonce = bytes.Clone(work.ResultNonce)
	}
	return connect.NewResponse(&devicev1.GetResourceWorkResponse{Work: work}), nil
}

func (s *dispatchServer) AuthorizeResourceStart(ctx context.Context, req *connect.Request[devicev1.AuthorizeResourceStartRequest]) (*connect.Response[devicev1.AuthorizeResourceStartResponse], error) {
	f := s.f
	f.remote(req.Msg.GetSessionEpoch())
	f.authorizations++
	if req.Msg.GetActionId() != f.work.GetActionId() || !bytes.Equal(req.Msg.GetChallengeProof(), f.challenge) {
		f.t.Fatal("server did not receive the exact protected challenge/action")
	}
	if err := f.phase(ctx, "authorize"); err != nil {
		return nil, err
	}
	f.work.StartGrantEnvelope = f.grant
	if f.loseAuthorization {
		f.loseAuthorization = false
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("response lost after grant committed"))
	}
	return connect.NewResponse(&devicev1.AuthorizeResourceStartResponse{StartGrantEnvelope: f.grant}), nil
}

func (s *dispatchServer) ReportResourceResult(ctx context.Context, req *connect.Request[devicev1.ReportResourceResultRequest]) (*connect.Response[devicev1.ReportResourceResultResponse], error) {
	f := s.f
	f.remote(req.Msg.GetSessionEpoch())
	if cancellation := req.Msg.GetNeverPrepared(); cancellation != nil {
		digest := sha256.Sum256(f.intent)
		if !f.neverPrepared || req.Msg.GetActionId() != f.work.GetActionId() || !bytes.Equal(cancellation.GetIntentSha256(), digest[:]) || !bytes.Equal(cancellation.GetResultNonce(), f.lastNonce) || len(req.Msg.GetAttestationEnvelope()) != 0 || len(req.Msg.GetCertificatePem()) != 0 {
			f.t.Fatal("never-prepared cancellation lost exact binding or fabricated native proof")
		}
	} else if req.Msg.GetActionId() != f.work.GetActionId() || req.Msg.GetSessionEpoch() != f.attestedEpoch || !bytes.Equal(req.Msg.GetAttestationEnvelope(), f.attestation) || !bytes.Equal(req.Msg.GetCertificatePem(), f.certificate) {
		f.t.Fatal("server did not receive the exact attestation/certificate/session")
	}
	if err := f.phase(ctx, "report"); err != nil {
		return nil, err
	}
	f.reports++
	f.closed = f.neverPrepared || serviceExecutionTerminal(f.attestedState)
	closed := f.closed
	if f.moreActions && closed {
		f.closed = false
		f.work.ActionId = fmt.Sprintf("11111111-1111-4111-8111-%012d", f.reports+1)
	}
	return connect.NewResponse(&devicev1.ReportResourceResultResponse{Closed: closed}), nil
}

var (
	_ agentv1connect.ExecutorServiceClient = (*dispatchExecutor)(nil)
	_ devicev1connect.DeviceServiceClient  = (*dispatchServer)(nil)
)
