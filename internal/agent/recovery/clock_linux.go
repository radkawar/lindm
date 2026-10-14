// SPDX-License-Identifier: Apache-2.0

//go:build linux

package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	recoveryv1connect "lindm/gen/lindm/recovery/v1/recoveryv1connect"
	"lindm/internal/trust"
)

// Clock is a boot-local authenticated UTC interval. It never reads or sets the
// RTC. CLOCK_BOOTTIME includes suspend, so sleeping cannot extend authority.
// The interval includes the entire bootstrap round trip rather than guessing
// symmetric network latency. It is never restored from a persisted timestamp.
type Clock struct {
	mu                   sync.Mutex
	monotonic            func() (time.Duration, error)
	attempted, ready     bool
	bootID               string
	serverTime           time.Time
	sent, received, last time.Duration
	floor                recoveryTrustFloor
}

type recoveryTrustFloor struct {
	rootVersion, delegationVersion, minimumEpoch uint64
	rootSHA256, delegationSHA256                 [sha256.Size]byte
}

func NewClock() *Clock { return &Clock{monotonic: bootTime} }

// Bounds returns the earliest/latest possible server time. Callers use the
// earliest for issued-at/not-before and the latest for expiration. Errors must
// prohibit authority; there is deliberately no wall-clock fallback.
func (c *Clock) Bounds() (time.Time, time.Time, error) {
	if c == nil {
		return time.Time{}, time.Time{}, errors.New("recovery_time_required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ready || c.monotonic == nil {
		return time.Time{}, time.Time{}, errors.New("recovery_time_not_authenticated")
	}
	now, err := c.monotonic()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if now < c.received || now < c.last {
		return time.Time{}, time.Time{}, errors.New("recovery_monotonic_clock_rollback")
	}
	c.last = now
	return c.serverTime.Add(now - c.received), c.serverTime.Add(now - c.sent), nil
}

func (c *Clock) bootstrap(ctx context.Context, verifier *trust.ExecutionVerifier, client recoveryv1connect.RecoveryServiceClient, record *agentv1.RecoveryJournal, delegation *agentv1.ExecutionDelegation, bootID string, minimum time.Time) error {
	if c == nil {
		return errors.New("recovery_time_required")
	}
	c.mu.Lock()
	if c.ready {
		sameBoot := c.bootID == bootID
		c.mu.Unlock()
		if !sameBoot {
			return errors.New("recovery_time_boot_changed")
		}
		lower, _, err := c.Bounds()
		if err != nil {
			return err
		}
		if lower.Before(minimum) {
			return errors.New("recovery_time_before_protected_state")
		}
		return nil
	}
	if c.attempted || c.monotonic == nil {
		c.mu.Unlock()
		return errors.New("recovery_time_bootstrap_consumed")
	}
	c.attempted = true
	c.mu.Unlock()
	rootDigest, err := trust.ExecutionRootDigest(record.GetAcceptedRoot())
	if err != nil {
		return err
	}
	delegationDigest := sha256.Sum256(record.GetDelegationEnvelope())
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	request := &recoveryv1.GetRecoveryTimeRequest{Nonce: nonce, BootId: bootID, RootVersion: record.GetAcceptedRoot().GetVersion(), RootSha256: rootDigest[:], DelegationVersion: delegation.GetVersion(), DelegationSha256: delegationDigest[:], MinimumRecoveryEpoch: delegation.GetMinimumRecoveryEpoch()}
	sent, err := c.monotonic()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := client.GetRecoveryTime(ctx, connect.NewRequest(request))
	if err != nil {
		return err
	}
	received, err := c.monotonic()
	if err != nil {
		return err
	}
	if received < sent || received-sent >= 30*time.Second {
		return errors.New("recovery_time_response_expired")
	}
	if response == nil || response.Msg == nil {
		return errors.New("recovery_time_response_missing")
	}
	statement, currentRoot, currentDelegation, err := verifier.VerifyRecoveryTime(ctx, record.GetAcceptedRoot(), response.Msg, request, minimum, received-sent)
	if err != nil {
		return err
	}
	admitted, err := c.monotonic()
	if err != nil {
		return err
	}
	if admitted < received || admitted-sent >= 30*time.Second {
		return errors.New("recovery_time_response_expired")
	}
	if err := unexpiredThrough(statement.GetServerTime().AsTime().Add(admitted-sent), statement.GetExpiresAt().AsTime(), currentRoot.GetExpiresAt().AsTime(), currentDelegation.GetExpiresAt().AsTime()); err != nil {
		return err
	}
	currentRootDigest, err := trust.ExecutionRootDigest(currentRoot)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.serverTime, c.sent, c.received, c.last = statement.GetServerTime().AsTime(), sent, received, admitted
	c.floor = recoveryTrustFloor{rootVersion: currentRoot.GetVersion(), delegationVersion: currentDelegation.GetVersion(), minimumEpoch: currentDelegation.GetMinimumRecoveryEpoch(), rootSHA256: currentRootDigest, delegationSHA256: sha256.Sum256(response.Msg.GetTrustUpdate().GetDelegationEnvelope())}
	c.bootID, c.ready = bootID, true
	c.mu.Unlock()
	return nil
}

func (r *runner) now() (time.Time, time.Time, error) { return r.clock.Bounds() }

func unexpiredThrough(latest time.Time, limits ...time.Time) error {
	for _, limit := range limits {
		if !latest.Before(limit) {
			return ErrAuthorityExpired
		}
	}
	return nil
}

// The authenticated clock bootstrap can also learn a revocation or new root.
// Do not permit subsequent action/snapshot responses to forget that knowledge.
// updateTrust durably saves the admitted authority before any effect.
func (c *Clock) acceptTrust(root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte) error {
	digest, err := trust.ExecutionRootDigest(root)
	if err != nil {
		return err
	}
	delegationDigest := sha256.Sum256(envelope)
	c.mu.Lock()
	defer c.mu.Unlock()
	floor := c.floor
	ready := c.ready
	if !ready || floor.rootVersion == 0 || root.GetVersion() < floor.rootVersion || delegation.GetVersion() < floor.delegationVersion || delegation.GetMinimumRecoveryEpoch() < floor.minimumEpoch {
		return errors.New("recovery_time_trust_rollback")
	}
	if root.GetVersion() == floor.rootVersion && digest != floor.rootSHA256 {
		return errors.New("recovery_time_root_substitution")
	}
	if delegation.GetVersion() == floor.delegationVersion && delegationDigest != floor.delegationSHA256 {
		return errors.New("recovery_time_delegation_substitution")
	}
	// Snapshot reads share this floor with subsequent execution. A newer
	// authenticated update cannot be forgotten even when the NV snapshot
	// intentionally restores an older exact journal.
	c.floor = recoveryTrustFloor{rootVersion: root.GetVersion(), delegationVersion: delegation.GetVersion(), minimumEpoch: delegation.GetMinimumRecoveryEpoch(), rootSHA256: digest, delegationSHA256: delegationDigest}
	return nil
}

// A chain starting at an older retained journal must pass through the exact
// root learned during bootstrap/snapshot, not a higher-version fork of it.
func (c *Clock) checkRootContinuity(root *agentv1.ExecutionRoot) error {
	c.mu.Lock()
	floor := c.floor
	c.mu.Unlock()
	if root.GetVersion() != floor.rootVersion {
		return nil
	}
	digest, err := trust.ExecutionRootDigest(root)
	if err != nil || digest != floor.rootSHA256 {
		return errors.New("recovery_time_root_substitution")
	}
	return nil
}
