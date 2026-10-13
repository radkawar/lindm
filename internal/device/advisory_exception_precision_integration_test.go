//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
)

func TestAdvisoryExceptionReceiptMatchesPersistedPrecision(t *testing.T) {
	parallelDeviceIntegration(t)
	f, request := advisoryAcceptanceFixture(t)
	request.ExpiresAt.Nanos = 446777608
	accepted, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	listed, err := f.svc.ListDeviceFindings(f.ownerCtx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: request.GetDeviceId()}))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Msg.GetFindings()) != 1 || !proto.Equal(listed.Msg.GetFindings()[0].GetException(), accepted.Msg.GetException()) {
		t.Fatalf("mutation receipt disagrees with persisted finding: receipt=%v findings=%v", accepted.Msg, listed.Msg)
	}
	if accepted.Msg.GetException().GetExpiresAt().GetNanos()%1000 != 0 {
		t.Fatal("response did not project database timestamp precision")
	}
	replayed, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(replayed.Msg, accepted.Msg) {
		t.Fatalf("exact original request retry changed persisted response: %v", err)
	}
}
