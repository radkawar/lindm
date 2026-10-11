package devlab

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/config"
	"lindm/internal/resource"
	"lindm/internal/trust"
)

// ConfigureDeviceActions installs private online signing and independent escrow
// transport/wrapping keys in the owned server, with two-person reveal required.
// The exact action delegation still needs normal Admin API admission. Only
// read-only encryption compliance is added; no service execution or wildcard
// capability is granted. Persistent fixtures restore the same delegation and
// custody on subsequent calls; disposable fixtures require a single call.
// Restarting preserves all accounts, sessions and the isolated database.
func (f *AuthorityFixture) ConfigureDeviceActions(ctx context.Context) (*agentv1.UpdateExecutionTrustRequest, error) {
	if f.connected != nil {
		return nil, errors.New("device action configuration requires controller-owned authority fixture")
	}
	if f.closed || f.local == nil {
		return nil, errors.New("device actions require an open local authority fixture")
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return nil, err
	}
	if document.Proto.GetEscrow() != nil || document.Proto.GetExecutionSigning() != nil {
		if f.persistent {
			encoded, err := readOwned(filepath.Join(f.directory, "actions-delegation.json"))
			if err != nil {
				return nil, err
			}
			update := new(agentv1.UpdateExecutionTrustRequest)
			if err := protojson.Unmarshal(encoded, update); err != nil {
				return nil, err
			}
			return update, nil
		}
		return nil, errors.New("device action custody is already configured")
	}
	capabilities, err := deviceActionCapabilities()
	if err != nil {
		return nil, err
	}
	// Read-only encryption compliance is qualified on the same encrypted guest.
	compliance, err := resource.Capability(resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE)
	if err != nil {
		return nil, err
	}
	keys, err := createExecutionTrustExerciseForLifetime(ctx, f.repository, append(capabilities, compliance), f.persistent)
	if err != nil {
		return nil, err
	}
	defer keys.Close()
	transport, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	for name, key := range map[string]any{"actions-plan.pem": keys.planKey, "actions-start.pem": keys.startKey, "escrow-transport.pem": transport} {
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
	var wrapping [32]byte
	if _, err := rand.Read(wrapping[:]); err != nil {
		return nil, err
	}
	defer clear(wrapping[:])
	if err := os.WriteFile(filepath.Join(f.directory, "escrow-wrapping.key"), wrapping[:], 0600); err != nil {
		return nil, err
	}
	document.Proto.ExecutionSigning = &configv1.ExecutionSigningConfig{PlanKeyFile: "actions-plan.pem", StartKeyFile: "actions-start.pem"}
	document.Proto.Escrow = &configv1.EscrowConfig{TransportKeyFile: "escrow-transport.pem", WrappingKeyFile: "escrow-wrapping.key", RevealApprovalRequired: true}
	if f.persistent {
		encoded, err := protojson.Marshal(keys.Initial)
		if err != nil {
			return nil, err
		}
		if err := writeSplitPrivateFile(filepath.Join(f.directory, "actions-delegation.json"), encoded); err != nil {
			return nil, err
		}
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

// Keep disposable console and native action lanes on the same exact capability
// registry. Production authority remains explicitly supplied by its offline owner.
func deviceActionCapabilities() ([]string, error) {
	specs := []*agentv1.DeviceActionSpec{
		{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{}}},
		{Action: &agentv1.DeviceActionSpec_Tpm2Bind{Tpm2Bind: &agentv1.TPM2BindAction{}}},
		{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}},
		{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{}}},
		{Action: &agentv1.DeviceActionSpec_Quarantine{Quarantine: &agentv1.QuarantineAction{}}},
		{Action: &agentv1.DeviceActionSpec_ReleaseQuarantine{ReleaseQuarantine: &agentv1.ReleaseQuarantineAction{}}},
		{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{}}},
		{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{}}},
		{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}},
		{Action: &agentv1.DeviceActionSpec_Shutdown{Shutdown: &agentv1.ShutdownAction{}}},
		{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}},
		{Action: &agentv1.DeviceActionSpec_LocalAdminPasswordRotate{LocalAdminPasswordRotate: &agentv1.LocalAdminPasswordRotateAction{}}},
		{Action: &agentv1.DeviceActionSpec_PatchNow{PatchNow: &agentv1.PatchNowAction{}}},
	}
	capabilities := make([]string, 0, len(specs))
	for _, spec := range specs {
		capability, err := trust.DeviceActionCapability(spec)
		if err != nil {
			return nil, err
		}
		capabilities = append(capabilities, capability)
	}
	return capabilities, nil
}
