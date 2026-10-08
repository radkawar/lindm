package devlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

// ExecutionTrustExercise contains only public signed requests for a disposable
// guest. Its successor root keys are discarded: never apply it to a retained
// installation. It neither replaces the development root nor publishes authority.
type ExecutionTrustExercise struct {
	Initial            *agentv1.UpdateExecutionTrustRequest
	WrongQuorum        *agentv1.UpdateExecutionTrustRequest
	Rotated            *agentv1.UpdateExecutionTrustRequest
	Revoked            *agentv1.UpdateExecutionTrustRequest
	DelegationRollback *agentv1.UpdateExecutionTrustRequest
	EpochRollback      *agentv1.UpdateExecutionTrustRequest
}

func CreateExecutionTrustExercise(ctx context.Context, repoRoot string) (result *ExecutionTrustExercise, err error) {
	err = locked(ctx, repoRoot, func(root string) error {
		fixture := FixturePath(root)
		if err := validateFixture(fixture); err != nil {
			return err
		}
		authority, err := trust.New()
		if err != nil {
			return err
		}
		directory := filepath.Join(fixture, "agent-trust")
		if err := verifyDevelopmentTrust(ctx, authority, directory); err != nil {
			return err
		}
		encoded, err := os.ReadFile(filepath.Join(directory, "execution-root.json"))
		if err != nil {
			return err
		}
		current := new(agentv1.ExecutionRoot)
		if err := protojson.Unmarshal(encoded, current); err != nil {
			return err
		}
		if current.GetVersion() != 1 {
			return errors.New("execution trust exercise requires the initial development root")
		}
		previousKeys := make([]ed25519.PrivateKey, 0, len(current.GetKeys()))
		nextKeys := make([]ed25519.PrivateKey, 0, len(current.GetKeys()))
		defer func() {
			for _, keys := range [][]ed25519.PrivateKey{previousKeys, nextKeys} {
				for _, key := range keys {
					clear(key)
				}
			}
		}()
		next := proto.CloneOf(current)
		next.Version++
		next.Keys = nil
		for i := range current.GetKeys() {
			encoded, err := os.ReadFile(filepath.Join(directory, fmt.Sprintf("execution-key-%d.pem", i)))
			if err != nil {
				return err
			}
			key, err := developmentPrivateKey(encoded)
			clear(encoded)
			if err != nil {
				return err
			}
			previousKeys = append(previousKeys, key)
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			nextKeys = append(nextKeys, private)
			id, err := trust.KeyID(public)
			if err != nil {
				return err
			}
			next.Keys = append(next.Keys, &agentv1.ExecutionKey{KeyId: id, PublicKey: public})
		}
		now := time.Now().UTC().Truncate(time.Second)
		// QEMU's guest clock may lag the publishing host slightly. Publish a
		// deliberate overlap; never relax the executor's signed time checks.
		notBefore := now.Add(-time.Minute)
		if notBefore.Before(current.GetNotBefore().AsTime()) {
			notBefore = current.GetNotBefore().AsTime()
		}
		expires := now.Add(2 * time.Hour)
		if expires.After(current.GetExpiresAt().AsTime()) {
			return errors.New("development execution root has less than two hours remaining")
		}
		var delegates []*agentv1.ExecutionDelegate
		for _, role := range []agentv1.ExecutionSignerRole{agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START} {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			clear(private)
			id, err := trust.KeyID(public)
			if err != nil {
				return err
			}
			delegates = append(delegates, &agentv1.ExecutionDelegate{Key: &agentv1.ExecutionKey{KeyId: id, PublicKey: public}, Role: role, Capabilities: []string{"systemd.service.v1"}})
		}
		delegation := &agentv1.ExecutionDelegation{
			DeploymentId: current.GetDeploymentId(), RootVersion: 1, Version: 1,
			NotBefore: timestamppb.New(notBefore), ExpiresAt: timestamppb.New(expires), Delegates: delegates,
		}
		initial, err := authority.Sign(ctx, delegation, previousKeys[:current.GetThreshold()]...)
		if err != nil {
			return err
		}
		delegation.RootVersion, delegation.Version, delegation.MinimumRecoveryEpoch = 2, 2, 1
		rotated, err := authority.Sign(ctx, delegation, nextKeys[:next.GetThreshold()]...)
		if err != nil {
			return err
		}
		delegation.Version, delegation.Delegates = 3, nil
		revoked, err := authority.Sign(ctx, delegation, nextKeys[:next.GetThreshold()]...)
		if err != nil {
			return err
		}
		oldEndorsement, err := authority.Sign(ctx, next, previousKeys[:current.GetThreshold()]...)
		if err != nil {
			return err
		}
		newEndorsement, err := authority.Sign(ctx, next, nextKeys[:next.GetThreshold()]...)
		if err != nil {
			return err
		}
		// Both negatives have valid current-root signatures and no transition.
		// Each isolates one fence instead of failing old-root authentication.
		delegation.Version = 1
		staleVersion, err := authority.Sign(ctx, delegation, nextKeys[:next.GetThreshold()]...)
		if err != nil {
			return err
		}
		delegation.Version, delegation.MinimumRecoveryEpoch = 4, 0
		staleEpoch, err := authority.Sign(ctx, delegation, nextKeys[:next.GetThreshold()]...)
		if err != nil {
			return err
		}
		result = &ExecutionTrustExercise{
			Initial:            &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: initial},
			WrongQuorum:        &agentv1.UpdateExecutionTrustRequest{RootTransitions: []*agentv1.ExecutionRootTransition{{PreviousQuorumEnvelope: newEndorsement, NextQuorumEnvelope: newEndorsement}}, DelegationEnvelope: rotated},
			Rotated:            &agentv1.UpdateExecutionTrustRequest{RootTransitions: []*agentv1.ExecutionRootTransition{{PreviousQuorumEnvelope: oldEndorsement, NextQuorumEnvelope: newEndorsement}}, DelegationEnvelope: rotated},
			Revoked:            &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: revoked},
			DelegationRollback: &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: staleVersion},
			EpochRollback:      &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: staleEpoch},
		}
		return nil
	})
	return result, err
}
