// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/agent/journal"
)

// DeviceActionProvider is the root-owned native effect boundary. The gate must
// run after native preflight and immediately before the first mutation. Native
// implementations cannot receive a caller-provided plan or choose authority.
type DeviceActionProvider interface {
	Observe(context.Context, *agentv1.DeviceActionSpec) (*agentv1.DeviceActionObservation, error)
	Plan(context.Context, *agentv1.DeviceActionSpec, *agentv1.DeviceActionObservation) (*agentv1.DeviceActionPlan, error)
	Apply(context.Context, *agentv1.DeviceActionPlan, []byte, func(context.Context) error) (*agentv1.DeviceActionVerification, error)
	Verify(context.Context, *agentv1.DeviceActionPlan, *agentv1.DeviceActionVerification) (*agentv1.DeviceActionVerification, error)
	ConfirmEscrow(context.Context, *agentv1.DeviceActionPlan, *agentv1.DeviceActionVerification, []byte, func(context.Context) error) (*agentv1.DeviceActionVerification, error)
	// StageLocalAdminPassword generates and escrow-seals a local-admin password
	// after the gate, without native change. The envelope is the only local copy.
	StageLocalAdminPassword(context.Context, *agentv1.DeviceActionPlan, func(context.Context) error) (*agentv1.DeviceActionVerification, *agentv1.PrivateCustodyEnvelope, error)
	// SetLocalAdminPassword sets the staged password after a verified receipt.
	SetLocalAdminPassword(context.Context, *agentv1.DeviceActionPlan, *agentv1.DeviceActionVerification, *agentv1.PrivateCustodyEnvelope, func(context.Context) error) (*agentv1.DeviceActionVerification, error)
}

// WithActionProvider installs the locally configured native provider. Absence
// denies new device actions; it does not disable reading protected history.
func WithActionProvider(provider DeviceActionProvider) Option {
	return func(s *Service) { s.actionProvider = provider }
}

// WithActionProviderFactory composes a provider with the same protected journal
// as the executor, once storage exists. It never opens a second journal owner.
func WithActionProviderFactory(factory func(*journal.Store) (DeviceActionProvider, error)) Option {
	return func(s *Service) { s.actionProviderFactory = factory }
}

func (s *Service) initializeActionProvider() error {
	if s.actionProviderFactory == nil || s.store == nil || s.hold {
		return nil
	}
	if s.actionProvider != nil {
		return errInvalid
	}
	provider, err := s.actionProviderFactory(s.store)
	if err != nil {
		return err
	}
	s.actionProvider = provider
	return nil
}

type deviceActionCredential struct {
	actionID string
	value    []byte
	expires  time.Time
}

func (s *Service) clearActionCredential() {
	releaseActionCredential(s.actionCredential.value)
	s.actionCredential = deviceActionCredential{}
}

func releaseActionCredential(value []byte) {
	if len(value) == 0 {
		return
	}
	clear(value)
	_ = unix.Munlock(value)
	_ = unix.Munmap(value)
}

// SupplyDeviceActionCredential is root-only in localrpc. It accepts a short-lived
// one-use owner credential, never a server-supplied secret or durable journal data.
func (s *Service) SupplyDeviceActionCredential(ctx context.Context, req *connect.Request[agentv1.SupplyDeviceActionCredentialRequest]) (*connect.Response[agentv1.SupplyDeviceActionCredentialResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || req.Msg == nil {
		return nil, mapError(errInvalid)
	}
	defer clear(req.Msg.Credential)
	if s.admit(req.Msg) != nil {
		return nil, mapError(errInvalid)
	}
	// Retained plaintext lives in a dedicated unswappable, non-dumpable mapping,
	// not in the garbage-collected heap or a file. Fail closed on either fence.
	value, err := unix.Mmap(-1, 0, len(req.Msg.GetCredential()), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, mapError(actionprovider.ErrUnsupported)
	}
	if err := unix.Mlock(value); err != nil {
		_ = unix.Munmap(value)
		return nil, mapError(actionprovider.ErrUnsupported)
	}
	if err := unix.Madvise(value, unix.MADV_DONTDUMP); err != nil {
		releaseActionCredential(value)
		return nil, mapError(actionprovider.ErrUnsupported)
	}
	copy(value, req.Msg.GetCredential())
	clear(req.Msg.Credential)
	retained := false
	defer func() {
		if !retained {
			releaseActionCredential(value)
		}
	}()
	if err := s.lock(ctx); err != nil {
		return nil, mapError(err)
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	record, _, err := s.loadDeviceAction(ctx, loaded, req.Msg.GetActionId())
	if err != nil {
		return nil, mapError(err)
	}
	if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED && record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW {
		return nil, mapError(errResourceRejected)
	}
	s.clearActionCredential()
	s.actionCredential = deviceActionCredential{actionID: req.Msg.GetActionId(), value: value, expires: s.now().Add(30 * time.Second)}
	retained = true
	return noStore(&agentv1.SupplyDeviceActionCredentialResponse{}), nil
}

// takeActionCredential transfers exclusive ownership; the native invocation
// clears the returned memory on every exit. A credential cannot cross actions.
func (s *Service) takeActionCredential(actionID string) []byte {
	if s.actionCredential.actionID != actionID || !s.now().Before(s.actionCredential.expires) {
		if !s.now().Before(s.actionCredential.expires) {
			s.clearActionCredential()
		}
		return nil
	}
	credential := s.actionCredential.value
	s.actionCredential = deviceActionCredential{}
	return credential
}
