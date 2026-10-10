//go:build linux

package actionprovider

import (
	"context"
	"errors"
	"slices"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestOpenTargetExplicitlyRequestsBlockTree(t *testing.T) {
	target := &agentv1.StorageTarget{LuksUuid: fixtureLUKS, Wwn: "root-wwn", Serial: "root-serial", SizeBytes: 64 << 20}
	stopped := errors.New("stop before opening any device")
	observed := false
	p := &Provider{config: &agentv1.DeviceActionProviderConfig{Targets: []*agentv1.QualifiedActionTarget{{Target: target}}}}
	p.run = func(_ context.Context, request nativeRequest) ([]byte, error) {
		observed = true
		if request.command != lsblk || !slices.Contains(request.args, "--tree") {
			t.Fatal("identity inheritance requires explicit lsblk tree when NAME is absent")
		}
		return nil, stopped
	}
	_, err := p.openTarget(t.Context(), &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{Target: target}}}, false)
	if !observed || !errors.Is(err, stopped) {
		t.Fatalf("native topology collection not reached: %v", err)
	}
}
