package devlab

import (
	"context"
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
	keys, err := CreateExecutionTrustExercise(ctx, f.repository)
	if err != nil {
		return nil, err
	}
	defer keys.Close()
	for name, key := range map[string]any{"dispatch-plan.pem": keys.planKey, "dispatch-start.pem": keys.startKey} {
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
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(f.configPath(), encoded, 0600); err != nil {
		return nil, err
	}
	if err := f.Restart(ctx); err != nil {
		return nil, err
	}
	return keys.Initial, nil
}
