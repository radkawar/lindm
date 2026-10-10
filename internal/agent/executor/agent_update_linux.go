package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/update"
)

// WithAgentUpdates is local root-owned opt-in; no RPC can enable updates or select
// a different ring, manager, repository or bootstrap release root.
func WithAgentUpdates(cfg *agentv1.AgentUpdateConfig) Option {
	return func(s *Service) {
		if cfg != nil {
			s.updateConfig = proto.CloneOf(cfg)
		}
	}
}

// agentUpdateBusy is called with the executor authority mutex held.
func (s *Service) agentUpdateBusy() bool { return s.updateHold || s.updates != nil && s.updates.Busy() }

// Resolve persisted update interlocks before admitting actions after a process
// restart, including when an operator has disabled future update polling.
func (s *Service) initializeAgentUpdates(ctx context.Context) error {
	if s.store == nil || s.hold {
		return nil
	}
	if s.updateConfig != nil {
		_, err := s.updateEngine(ctx)
		if errors.Is(err, errPendingEnrollment) {
			return nil
		}
		return err
	}
	directory := filepath.Join(s.directory, "updates")
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		s.updateHold = true
		return nil
	}
	state := &agentv1.AgentUpdateJournal{}
	err := journal.ReadUpdateRecord(directory, "state.pb", state)
	if err == nil {
		err = s.admit(state)
	}
	s.updateHold = err != nil || state.GetPhase() != "idle" && state.GetPhase() != "installed" && state.GetPhase() != "rejected"
	return nil
}

func (s *Service) updateEngine(ctx context.Context) (*update.Engine, error) {
	if s.updateConfig == nil {
		return nil, nil
	}
	// loadBound rejects protected report-only live-root state. Pending recovery
	// handoff is equally exclusive: update cannot replace its executable/state.
	loaded, err := s.loadBound(ctx)
	if err != nil {
		return nil, err
	}
	if s.recoveryPending != nil {
		return nil, errServiceRejected
	}
	if loaded.state.GetDeviceId() == "" {
		return nil, errPendingEnrollment
	}
	if s.updates == nil {
		engine, err := update.New(s.workerContext, s.directory, loaded.state.GetDeviceId(), loaded.bootstrap.Bundle.GetReleaseRootJson(), s.updateConfig)
		if err != nil {
			return nil, err
		}
		s.updates = engine
	}
	return s.updates, nil
}

func (s *Service) ExchangeAgentUpdate(ctx context.Context, req *connect.Request[agentv1.ExchangeAgentUpdateRequest]) (*connect.Response[agentv1.ExchangeAgentUpdateResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	if err := s.admit(req.Msg); err != nil {
		return nil, mapError(err)
	}
	if err := s.lock(ctx); err != nil {
		return nil, mapError(err)
	}
	engine, err := s.updateEngine(ctx)
	if err != nil {
		s.mu.Unlock()
		return nil, mapError(err)
	}
	if engine == nil {
		s.mu.Unlock()
		return noStore(&agentv1.ExchangeAgentUpdateResponse{Status: &agentv1.AgentUpdateStatus{Phase: "disabled"}, PollIntervalSeconds: 60}), nil
	}
	if req.Msg.GetRequestId() == "" {
		if !s.actionMu.TryLock() {
			s.mu.Unlock()
			return nil, mapError(errServiceRejected)
		}
		blocked, scanErr := s.store.DeviceActionsBlockUpdate(ctx)
		if scanErr == nil && !blocked {
			scanErr = engine.Begin()
		}
		s.actionMu.Unlock()
		if scanErr != nil {
			s.mu.Unlock()
			return nil, mapError(scanErr)
		}
		if blocked {
			s.mu.Unlock()
			return nil, mapError(errServiceRejected)
		}
	}
	s.operations.Add(1)
	// Never retain identity/journal lock across a network-process callback.
	s.mu.Unlock()
	defer s.operations.Done()
	response, err := engine.Exchange(ctx, req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("agent_update_transport_rejected"))
	}
	return noStore(response), nil
}

func (s *Service) GetAgentUpdate(ctx context.Context, req *connect.Request[agentv1.GetAgentUpdateRequest]) (*connect.Response[agentv1.GetAgentUpdateResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	if err := s.admit(req.Msg); err != nil {
		return nil, mapError(err)
	}
	if err := s.lock(ctx); err != nil {
		return nil, mapError(err)
	}
	defer s.mu.Unlock()
	if s.liveRoot != nil {
		return nil, mapError(errServiceRejected)
	}
	engine, err := s.updateEngine(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	if engine == nil {
		return noStore(&agentv1.GetAgentUpdateResponse{Status: &agentv1.AgentUpdateStatus{Phase: "disabled"}}), nil
	}
	return noStore(&agentv1.GetAgentUpdateResponse{Status: engine.Status()}), nil
}
