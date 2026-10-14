// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/resource"
	"lindm/internal/trust"
)

func executionAuthority(ctx context.Context, o Options, deployment string, uid, gid int, custody *authorityCustody) error {
	a, err := trust.New()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	root := &agentv1.ExecutionRoot{DeploymentId: deployment, Version: 1, Threshold: 2, NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.AddDate(10, 0, 0))}
	private := make([]ed25519.PrivateKey, 0, 3)
	defer func() {
		for _, key := range private {
			clear(key)
		}
	}()
	for i := range 3 {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		private = append(private, key)
		id, err := trust.KeyID(pub)
		if err != nil {
			return err
		}
		root.Keys = append(root.Keys, &agentv1.ExecutionKey{KeyId: id, PublicKey: pub})
		if err := custody.sealRoot(uint32(i+1), key); err != nil {
			return err
		}
	}
	rootJSON, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(root)
	if err != nil {
		return err
	}
	if err := newFile("/etc/lindm/execution-root.json", rootJSON, uid, gid, 0600); err != nil {
		return err
	}
	// The release root is the release custodian's authenticated public artifact;
	// never create a new empty update authority on the installed server.
	releaseRoot, err := os.ReadFile(filepath.Join(o.Bundle, "release-root.json"))
	if err != nil {
		return fmt.Errorf("authenticated custodian TUF release-root.json is required: %w", err)
	}
	transport, err := os.ReadFile("/etc/lindm/transport-ca.crt")
	if err != nil {
		return err
	}
	console, err := os.ReadFile("/etc/lindm/console-ca.crt")
	if err != nil {
		return err
	}
	// Both per-origin roots are quorum-signed, never merged: an approved console
	// issuer must not become authority for the independent device TLS endpoint.
	device, err := os.ReadFile("/etc/lindm/device-ca.crt")
	if err != nil {
		return err
	}
	digest := sha256.Sum256(rootJSON)
	bundle := &agentv1.BootstrapBundle{BundleId: uuid.NewString(), DeploymentId: deployment, EnrollmentOrigin: o.Origin, DeviceOrigin: o.DeviceOrigin, TransportCaPem: transport, ConsoleCaPem: console, DeviceCaPem: device, ExecutionRootVersion: 1, ExecutionRootSha256: digest[:], ReleaseRootJson: releaseRoot, NotBefore: root.NotBefore, ExpiresAt: root.ExpiresAt}
	encoded, err := a.Sign(ctx, bundle, private[:2]...)
	if err != nil {
		return err
	}
	if _, err := a.VerifyBootstrap(ctx, rootJSON, encoded, now); err != nil {
		return err
	}
	if err := newFile("/etc/lindm/bootstrap.dsse.json", encoded, uid, gid, 0600); err != nil {
		return err
	}
	capabilities := []string{trust.CapabilityPolicyCapability}
	for _, kind := range resource.ExecutableKinds() {
		c, err := resource.Capability(kind)
		if err != nil {
			return err
		}
		capabilities = append(capabilities, c)
	}
	capabilities = append(capabilities, "device.escrow-rotate.v1", "device.tpm2-bind.v1", "device.lock-sessions.v1", "device.release-lock.v1", "device.quarantine.v1", "device.release-quarantine.v1", "device.crypto-erase.v1", "device.sanitize.v1", "device.restart.v1", "device.shutdown.v1", "device.refresh-inventory.v1", "device.local-admin-rotate.v1", "device.patch-now.v1")
	delegation := &agentv1.ExecutionDelegation{DeploymentId: deployment, RootVersion: 1, Version: 1, NotBefore: root.NotBefore, ExpiresAt: timestamppb.New(now.AddDate(1, 0, 0))}
	for i, role := range []agentv1.ExecutionSignerRole{agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		id, err := trust.KeyID(pub)
		if err != nil {
			clear(key)
			return err
		}
		name := []string{"plan.key", "start.key"}[i]
		err = writeKey("/etc/lindm/"+name, key, uid, gid)
		clear(key)
		if err != nil {
			return err
		}
		delegation.Delegates = append(delegation.Delegates, &agentv1.ExecutionDelegate{Key: &agentv1.ExecutionKey{KeyId: id, PublicKey: pub}, Role: role, Capabilities: capabilities})
	}
	encoded, err = a.Sign(ctx, delegation, private[:2]...)
	if err != nil {
		return err
	}
	request, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(&agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: encoded})
	if err != nil {
		return err
	}
	if err := newFile("/etc/lindm/execution-delegation.json", request, uid, gid, 0600); err != nil {
		return err
	}
	return custody.export(o, deployment, root, gid)
}

func writeKey(path string, key crypto.Signer, uid, gid int) error {
	encoded, err := privateKeyPEM(key)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return newFile(path, encoded, uid, gid, 0600)
}
