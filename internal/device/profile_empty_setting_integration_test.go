//go:build integration

package device

import (
	"errors"
	"fmt"
	"testing"

	validate "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Owner pass 2 bug 1: the console must locate the refused setting, so the
// refusal carries its request field path in the schema-violation shape.
func TestPublishRefusesEmptySettingAtItsFieldPath(t *testing.T) {
	f := newDispatchFixture(t)
	spec := proto.CloneOf(f.revision.GetSpec())
	zone := proto.CloneOf(spec.Resources[0])
	zoneID := uuid.NewString()
	zone.ResourceId = uuid.NewString()
	zone.DependsOn = nil
	zone.Desired = &resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE, CanonicalKey: zoneID},
		State: &resourcev1.ResourceDesiredState_FirewallZone{FirewallZone: &resourcev1.FirewallZoneDesired{
			ZoneId: zoneID, Presence: resourcev1.Presence_PRESENCE_PRESENT,
			DefaultIngress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_DROP, DefaultEgress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT,
		}},
	}
	spec.Resources = append(spec.Resources, zone)
	_, err := f.service.PublishProfileRevision(f.adminCtx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{
		RequestId: uuid.NewString(), ProfileId: f.revision.GetProfileId(), ExpectedRevisionId: proto.String(f.revision.GetRevisionId()), Spec: spec, Reason: "publish an empty firewall zone",
	}))
	dispatchError(t, err, connect.CodeInvalidArgument, "profile_setting_empty")
	var rpc *connect.Error
	if !errors.As(err, &rpc) {
		t.Fatalf("not a connect error: %v", err)
	}
	var violations *validate.Violations
	for _, detail := range rpc.Details() {
		value, err := detail.Value()
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := value.(*validate.Violations); ok {
			violations = v
		}
	}
	if len(violations.GetViolations()) != 1 {
		t.Fatalf("violations=%v", violations)
	}
	field := violations.GetViolations()[0].GetField()
	index := len(spec.Resources) - 1
	if path := protovalidate.FieldPathString(field); path != fmt.Sprintf("spec.resources[%d].desired.firewall_zone", index) || field.GetElements()[1].GetIndex() != uint64(index) {
		t.Fatalf("refusal path=%s", path)
	}
	head, err := f.service.GetProfileRevision(f.adminCtx, connect.NewRequest(&adminv1.GetProfileRevisionRequest{ProfileId: f.revision.GetProfileId()}))
	if err != nil || head.Msg.GetRevision().GetRevisionId() != f.revision.GetRevisionId() {
		t.Fatalf("refused publication changed the head: %v", err)
	}
}
