package journal

import (
	"strconv"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/privatecustody"
)

// Only identifiers of the root-planned binding enter the custody context; the
// installation key keeps the envelope useless outside this journal.
func (s *Store) localAdminBinding(binding *agentv1.LocalAdminPasswordBinding) []byte {
	return privatecustody.Binding("lindm.local-admin-password.v1", s.installationID, binding.GetDeviceId(), binding.GetEnrollmentGeneration(), binding.GetActionId(), binding.GetAccountName(), strconv.FormatUint(uint64(binding.GetAccountUid()), 10))
}

// SealLocalAdminPassword encrypts one generated password for exactly the
// action/account binding. The caller retains and clears the plaintext. The
// envelope is persisted only inside that action's DeviceActionRecord.
func (s *Store) SealLocalAdminPassword(binding *agentv1.LocalAdminPasswordBinding, password []byte) (*agentv1.PrivateCustodyEnvelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil || s.privateCustody == nil {
		return nil, ErrClosed
	}
	if binding == nil || binding.GetActionId() == "" || binding.GetAccountUid() == 0 || len(password) == 0 {
		return nil, ErrDeviceActionRejected
	}
	envelope, err := s.privateCustody.Seal(password, s.localAdminBinding(binding))
	if err != nil {
		return nil, ErrRecoveryHold
	}
	return envelope, nil
}

// OpenLocalAdminPassword returns a fresh caller-owned plaintext buffer; clear it
// immediately after the native set. A different binding or key fails closed.
func (s *Store) OpenLocalAdminPassword(binding *agentv1.LocalAdminPasswordBinding, envelope *agentv1.PrivateCustodyEnvelope) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil || s.privateCustody == nil {
		return nil, ErrClosed
	}
	if binding == nil || envelope == nil {
		return nil, ErrDeviceActionRejected
	}
	password, err := s.privateCustody.Open(envelope, s.localAdminBinding(binding))
	if err != nil {
		return nil, ErrRecoveryHold
	}
	return password, nil
}
