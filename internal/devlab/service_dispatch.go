// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
)

// ConfigureServiceDispatch installs fresh online keys in the private real server.
// The returned offline-root-signed delegation still requires normal Admin API
// admission. Only lindmd signs plans and start grants in the connected lane.
func (f *AuthorityFixture) ConfigureServiceDispatch(ctx context.Context) (*agentv1.UpdateExecutionTrustRequest, error) {
	return f.configureServiceDispatch(ctx, false)
}

// ConfigureServiceDispatchWithEscrow additionally installs fresh escrow
// transport and wrapping keys, the managed secret store's KEK and the
// local-admin password transport, with two-person reveal required.
func (f *AuthorityFixture) ConfigureServiceDispatchWithEscrow(ctx context.Context) (*agentv1.UpdateExecutionTrustRequest, error) {
	return f.configureServiceDispatch(ctx, true)
}

func (f *AuthorityFixture) configureServiceDispatch(ctx context.Context, escrow bool) (*agentv1.UpdateExecutionTrustRequest, error) {
	keys, err := CreateExecutionTrustExercise(ctx, f.repository)
	if err != nil {
		return nil, err
	}
	defer keys.Close()
	privateKeys := map[string]any{"dispatch-plan.pem": keys.planKey, "dispatch-start.pem": keys.startKey}
	if escrow {
		transport, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, err
		}
		privateKeys["dispatch-escrow-transport.pem"] = transport
	}
	for name, key := range privateKeys {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		clear(der)
		err = os.WriteFile(filepath.Join(f.directory, name), encoded, 0600)
		clear(encoded)
		if err != nil {
			return nil, err
		}
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return nil, err
	}
	document.Proto.ExecutionSigning = &configv1.ExecutionSigningConfig{PlanKeyFile: "dispatch-plan.pem", StartKeyFile: "dispatch-start.pem"}
	if escrow {
		var wrapping [32]byte
		if _, err := rand.Read(wrapping[:]); err != nil {
			return nil, err
		}
		err := os.WriteFile(filepath.Join(f.directory, "dispatch-escrow-wrapping.key"), wrapping[:], 0600)
		clear(wrapping[:])
		if err != nil {
			return nil, err
		}
		document.Proto.Escrow = &configv1.EscrowConfig{TransportKeyFile: "dispatch-escrow-transport.pem", WrappingKeyFile: "dispatch-escrow-wrapping.key", RevealApprovalRequired: true}
	}
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return nil, err
	}
	if err := f.writeConfig(encoded); err != nil {
		return nil, err
	}
	if err := f.Restart(ctx); err != nil {
		return nil, err
	}
	return keys.Initial, nil
}
