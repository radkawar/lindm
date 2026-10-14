// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/resource"
	"lindm/internal/trust"
)

// ExecutionTrustExercise holds public signed trust requests and private,
// short-lived online keys for disposable guest proofs. Close discards those keys.
// Successor offline root keys are discarded before return. Never apply these
// requests to a retained installation or publish them as production authority.
type ExecutionTrustExercise struct {
	Initial            *agentv1.UpdateExecutionTrustRequest
	WrongQuorum        *agentv1.UpdateExecutionTrustRequest
	Rotated            *agentv1.UpdateExecutionTrustRequest
	Revoked            *agentv1.UpdateExecutionTrustRequest
	DelegationRollback *agentv1.UpdateExecutionTrustRequest
	EpochRollback      *agentv1.UpdateExecutionTrustRequest
	authority          *trust.Authority
	deploymentID       string
	planKey            ed25519.PrivateKey
	startKey           ed25519.PrivateKey
	deviceCA           *x509.Certificate
}

func CreateExecutionTrustExercise(ctx context.Context, repoRoot string) (result *ExecutionTrustExercise, err error) {
	capabilities, err := defaultExecutionCapabilities()
	if err != nil {
		return nil, err
	}
	return createExecutionTrustExercise(ctx, repoRoot, capabilities)
}

// defaultExecutionCapabilities is every exact capability a disposable or demo
// fixture delegates: device actions, the resource kinds with an agent provider
// (server-side qualification still gates dispatch) and signed agent capability
// policies.
func defaultExecutionCapabilities() ([]string, error) {
	actions, err := deviceActionCapabilities()
	if err != nil {
		return nil, err
	}
	for _, kind := range resource.ExecutableKinds() {
		capability, err := resource.Capability(kind)
		if err != nil {
			return nil, err
		}
		actions = append(actions, capability)
	}
	return append(actions, trust.CapabilityPolicyCapability), nil
}

func createExecutionTrustExercise(ctx context.Context, repoRoot string, capabilities []string) (result *ExecutionTrustExercise, err error) {
	return createExecutionTrustExerciseForLifetime(ctx, repoRoot, capabilities, false)
}

func createExecutionTrustExerciseForLifetime(ctx context.Context, repoRoot string, capabilities []string, persistent bool) (result *ExecutionTrustExercise, err error) {
	var onlineKeys []ed25519.PrivateKey
	defer func() {
		if err != nil {
			for _, key := range onlineKeys {
				clear(key)
			}
		}
	}()
	err = locked(ctx, repoRoot, func(root string) error {
		fixture := FixturePath(root)
		if err := validateAuthorityFixture(fixture); err != nil {
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
		notBefore := now.Add(-trust.MaxDeviceClockSkew)
		if notBefore.Before(current.GetNotBefore().AsTime()) {
			notBefore = current.GetNotBefore().AsTime()
		}
		expires := now.Add(4 * time.Hour)
		if persistent {
			expires = current.GetExpiresAt().AsTime()
		}
		if expires.After(current.GetExpiresAt().AsTime()) {
			return errors.New("development execution root has less than four hours remaining")
		}
		var delegates []*agentv1.ExecutionDelegate
		for _, role := range []agentv1.ExecutionSignerRole{agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START} {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			onlineKeys = append(onlineKeys, private)
			id, err := trust.KeyID(public)
			if err != nil {
				return err
			}
			delegates = append(delegates, &agentv1.ExecutionDelegate{Key: &agentv1.ExecutionKey{KeyId: id, PublicKey: public}, Role: role, Capabilities: capabilities})
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
		caBytes, err := os.ReadFile(filepath.Join(fixture, "device-ca.crt"))
		if err != nil {
			return err
		}
		deviceCA, err := serviceExerciseCertificate(caBytes)
		if err != nil {
			return err
		}
		result = &ExecutionTrustExercise{
			authority: authority, deploymentID: current.GetDeploymentId(),
			planKey: onlineKeys[0], startKey: onlineKeys[1], deviceCA: deviceCA,
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
