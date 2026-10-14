// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"path/filepath"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/protodata"
)

// RecoveryDocument holds only public configuration and trust material. The
// one-action private key is opened separately by the selected custody backend.
// It is not an ordinary agent identity or an alternate enrollment configuration.
type RecoveryDocument struct {
	Proto         *agentv1.RecoveryRuntimeConfig
	ExecutionRoot []byte
	Bootstrap     []byte
	ServerCA      []byte
	Capsule       []byte
}

func LoadRecovery(path string) (*RecoveryDocument, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := readConfig(absolute, true)
	if err != nil {
		return nil, fmt.Errorf("read recovery configuration: %w", err)
	}
	cfg := new(agentv1.RecoveryRuntimeConfig)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("decode recovery configuration: %w", err)
	}
	if err := protodata.ValidateClosed(cfg.ProtoReflect()); err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(cfg); err != nil {
		return nil, fmt.Errorf("validate recovery configuration: %w", err)
	}
	base := filepath.Dir(absolute)
	state, err := canonicalDirectory(resolve(base, cfg.GetStateDirectory()))
	if err != nil {
		return nil, fmt.Errorf("recovery state directory: %w", err)
	}
	cfg.StateDirectory = state
	if cfg.GetKeyFile() != "" {
		cfg.KeyFile = resolve(base, cfg.GetKeyFile())
	}
	provider := cfg.GetProvider()
	if !provider.GetRecoveryEnvironment() || resolve(base, provider.GetProtectedStateDirectory()) != state {
		return nil, errors.New("recovery provider must use the actual protected recovery state directory")
	}
	provider.ProtectedStateDirectory = state
	cfg.RootFile = resolve(base, cfg.GetRootFile())
	cfg.BootstrapFile = resolve(base, cfg.GetBootstrapFile())
	cfg.ServerCaFile = resolve(base, cfg.GetServerCaFile())
	root, err := readConfig(cfg.GetRootFile(), true)
	if err != nil {
		return nil, fmt.Errorf("read authenticated recovery execution root: %w", err)
	}
	bundle, err := readConfig(cfg.GetBootstrapFile(), true)
	if err != nil {
		return nil, fmt.Errorf("read authenticated recovery bootstrap: %w", err)
	}
	ca, err := readConfig(cfg.GetServerCaFile(), true)
	if err != nil {
		return nil, fmt.Errorf("read recovery server CA: %w", err)
	}
	var capsule []byte
	if cfg.GetCustody() == agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM {
		capsule, err = readConfig(filepath.Join(state, "capsule.pb"), true)
		if err != nil {
			return nil, fmt.Errorf("read opaque TPM recovery capsule: %w", err)
		}
	}
	return &RecoveryDocument{Proto: cfg, ExecutionRoot: root, Bootstrap: bundle, ServerCA: ca, Capsule: capsule}, nil
}
