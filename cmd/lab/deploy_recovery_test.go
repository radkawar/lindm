// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

func TestDeployRecoveryVerifiesInstalledDelegationRequest(t *testing.T) {
	ctx := context.Background()
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &agentv1.ExecutionRoot{DeploymentId: "00000000-0000-4000-8000-000000000001", Version: 1, Threshold: 2, NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(time.Hour))}
	keys := make([]ed25519.PrivateKey, 0, 2)
	for range 2 {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id, err := trust.KeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		root.Keys = append(root.Keys, &agentv1.ExecutionKey{KeyId: id, PublicKey: public})
		keys = append(keys, private)
	}
	declaration := &agentv1.ExecutionDelegation{DeploymentId: root.GetDeploymentId(), RootVersion: 1, Version: 1, NotBefore: root.NotBefore, ExpiresAt: root.ExpiresAt}
	envelope, err := authority.Sign(ctx, declaration, keys...)
	if err != nil {
		t.Fatal(err)
	}
	request, err := protojson.Marshal(&agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: envelope})
	if err != nil {
		t.Fatal(err)
	}
	verified := new(agentv1.ExecutionDelegation)
	if err := verifyDeployDelegationRequest(ctx, authority, root, request, verified); err != nil {
		t.Fatal(err)
	}
	if verified.GetDeploymentId() != root.GetDeploymentId() || verified.GetVersion() != 1 {
		t.Fatal("installed request did not retain its signed delegation")
	}
	oneSignature, err := authority.Sign(ctx, declaration, keys[:1]...)
	if err != nil {
		t.Fatal(err)
	}
	insufficient, err := protojson.Marshal(&agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: oneSignature})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"raw envelope is not an installed request": envelope, "missing envelope": []byte("{}"), "malformed request": []byte("{"), "invalid envelope": []byte(`{"delegationEnvelope":"bm90LXNpZ25lZA=="}`), "insufficient quorum": insufficient} {
		t.Run(name, func(t *testing.T) {
			if err := verifyDeployDelegationRequest(ctx, authority, root, body, new(agentv1.ExecutionDelegation)); err == nil {
				t.Fatal("accepted invalid or unauthenticated installed delegation request")
			}
		})
	}
}
