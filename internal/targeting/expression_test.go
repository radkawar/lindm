package targeting

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/targeting/targetingdb"
)

func TestExpressionUnknownDoesNotBecomeNegatedMembership(t *testing.T) {
	e := &adminv1.TargetExpression{InventoryMaxAgeSeconds: 60, Nodes: []*adminv1.TargetNode{
		{Depth: 1, Node: &adminv1.TargetNode_Predicate{Predicate: &adminv1.DeviceFilter{OsId: "debian"}}},
		{Depth: 2, Node: &adminv1.TargetNode_NotIndex{NotIndex: 0}},
	}}
	d := targetingdb.TargetingDeviceRow{OsID: "debian", OsIDStatus: 1}
	if got := evaluate(e, d, &adminv1.DeviceMetadata{}, time.Unix(1000, 0)); got != unknown {
		t.Fatalf("NOT unknown selected membership: %v", got)
	}
	d.HostReceivedAt = pgtype.Timestamptz{Time: time.Unix(990, 0), Valid: true}
	if got := evaluate(e, d, &adminv1.DeviceMetadata{}, time.Unix(1000, 0)); got != excluded {
		t.Fatalf("NOT true = %v", got)
	}
}
func TestExpressionGraphRejectsForwardEdgesAndFalseRanks(t *testing.T) {
	for _, nodes := range [][]*adminv1.TargetNode{
		{{Depth: 1, Node: &adminv1.TargetNode_NotIndex{NotIndex: 0}}},
		{{Depth: 1, Node: &adminv1.TargetNode_Predicate{Predicate: &adminv1.DeviceFilter{}}}, {Depth: 1, Node: &adminv1.TargetNode_NotIndex{NotIndex: 0}}},
	} {
		if err := validateExpression(&adminv1.TargetExpression{Nodes: nodes}); err == nil {
			t.Fatal("cyclic or nondecreasing graph accepted")
		}
	}
}
func TestTargetExpressionValidationBounds(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	r := &adminv1.PutDynamicGroupRequest{RequestId: uuid.NewString(), Reason: "Bounded expression", Group: &adminv1.DynamicTargetGroup{GroupId: uuid.NewString(), Name: "bounded", Expression: &adminv1.TargetExpression{InventoryMaxAgeSeconds: 60}}}
	for range 65 {
		r.Group.Expression.Nodes = append(r.Group.Expression.Nodes, &adminv1.TargetNode{Depth: 1, Node: &adminv1.TargetNode_Predicate{Predicate: &adminv1.DeviceFilter{}}})
	}
	if err := s.validate(r); err == nil {
		t.Fatal("65 AST nodes accepted")
	}
	r.Group.Expression.Nodes = r.Group.Expression.Nodes[:1]
	r.Group.Expression.Nodes[0].Depth = 9
	if err := s.validate(r); err == nil {
		t.Fatal("depth nine accepted")
	}
}
func TestTargetExpressionTypedAttributesRemainClosed(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]*adminv1.AttributeValue{
		"rack":    {Value: &adminv1.AttributeValue_IntValue{IntValue: 0}},
		"enabled": {Value: &adminv1.AttributeValue_BoolValue{BoolValue: false}},
		"label":   {Value: &adminv1.AttributeValue_StringValue{StringValue: ""}},
		"zone":    {Value: &adminv1.AttributeValue_EnumValue{EnumValue: "west"}},
	}
	request := &adminv1.PutDynamicGroupRequest{
		RequestId: uuid.NewString(),
		Reason:    "Select typed attributes",
		Group: &adminv1.DynamicTargetGroup{
			GroupId: uuid.NewString(),
			Name:    "typed attributes",
			Expression: &adminv1.TargetExpression{InventoryMaxAgeSeconds: 60, Nodes: []*adminv1.TargetNode{
				{Depth: 1, Node: &adminv1.TargetNode_Predicate{Predicate: &adminv1.DeviceFilter{Attributes: values}}},
			}},
		},
	}
	if err := s.validate(request); err != nil {
		t.Fatalf("typed attribute values rejected: %v", err)
	}
	for _, name := range []string{"request", "group", "expression", "node", "filter", "attribute"} {
		t.Run(name, func(t *testing.T) {
			bad := proto.CloneOf(request)
			node := bad.Group.Expression.Nodes[0]
			messages := map[string]proto.Message{
				"request": bad, "group": bad.Group, "expression": bad.Group.Expression,
				"node": node, "filter": node.GetPredicate(), "attribute": node.GetPredicate().Attributes["rack"],
			}
			messages[name].ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
			if err := s.validate(bad); !errors.Is(err, ErrRejected) {
				t.Fatalf("unknown field admitted: %v", err)
			}
		})
	}
	for _, name := range []string{"missing value", "invalid key"} {
		t.Run(name, func(t *testing.T) {
			bad := proto.CloneOf(request)
			attributes := bad.Group.Expression.Nodes[0].GetPredicate().Attributes
			if name == "missing value" {
				attributes["rack"] = &adminv1.AttributeValue{}
			} else {
				attributes["Invalid key"] = attributes["rack"]
			}
			if err := s.validate(bad); !errors.Is(err, ErrRejected) {
				t.Fatalf("invalid attribute admitted: %v", err)
			}
		})
	}
	reordered := proto.CloneOf(request)
	reordered.Group.Expression.Nodes[0].GetPredicate().Attributes = make(map[string]*adminv1.AttributeValue, len(values))
	for _, key := range []string{"zone", "label", "enabled", "rack"} {
		reordered.Group.Expression.Nodes[0].GetPredicate().Attributes[key] = proto.CloneOf(values[key])
	}
	first, err := encoded(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encoded(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || !bytes.Equal(digest("targeting.group.put", first), digest("targeting.group.put", second)) {
		t.Fatal("attribute map order changed canonical request or digest")
	}
	decoded := new(adminv1.PutDynamicGroupRequest)
	if err := proto.Unmarshal(first, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(request, decoded) {
		t.Fatal("canonical encoding lost typed zero attribute presence")
	}
	if err := validateTargetingClosed((&adminv1.DeviceMetadata{Attributes: values}).ProtoReflect()); !errors.Is(err, ErrRejected) {
		t.Fatalf("unreviewed map field admitted: %v", err)
	}
}
func TestBucketUsesFullDigestAndImmutableIdentity(t *testing.T) {
	campaign := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	device := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	salt := make([]byte, 32)
	bytes := append([]byte("lindm.rollout.bucket.v1\x00"), campaign[:]...)
	bytes = append(bytes, salt...)
	bytes = append(bytes, device[:]...)
	sum := sha256.Sum256(bytes)
	expected := new(big.Int).Mod(new(big.Int).SetBytes(sum[:]), big.NewInt(10000)).Uint64()
	if got := Bucket(campaign, salt, device); uint64(got) != expected {
		t.Fatalf("bucket %d != full SHA256 remainder %d", got, expected)
	}
}
