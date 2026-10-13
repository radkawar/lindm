package targeting

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/wrapperspb"

	adminv1 "lindm/gen/lindm/admin/v1"
)

func TestDocumentAndJSONCapacityAreIndependent(t *testing.T) {
	if _, err := encoded(wrapperspb.Bytes(make([]byte, maxDocumentBytes+1))); !errors.Is(err, ErrCapacity) {
		t.Fatalf("oversized protobuf encoding: %v", err)
	}
	if _, err := encodedCatalog(wrapperspb.Bytes(make([]byte, maxCatalogBytes+1))); !errors.Is(err, ErrCapacity) {
		t.Fatalf("oversized catalog encoding: %v", err)
	}
	response := wrapperspb.Bytes(make([]byte, 800000))
	if _, err := encoded(response); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResponse(response); !errors.Is(err, ErrCapacity) {
		t.Fatalf("JSON base64 expansion escaped response ceiling: %v", err)
	}
	if err := ValidateResponse(wrapperspb.Bytes([]byte("bounded"))); err != nil {
		t.Fatal(err)
	}
}
func TestAttributeValueMatchesDefinitionSemantics(t *testing.T) {
	definition := &adminv1.AttributeDefinition{Key: "ring", Type: adminv1.AttributeType_ATTRIBUTE_TYPE_ENUM, EnumValues: []string{"canary", "fleet"}}
	if !AttributeValueMatches(definition, &adminv1.AttributeValue{Value: &adminv1.AttributeValue_EnumValue{EnumValue: "canary"}}) {
		t.Fatal("declared enum value rejected")
	}
	if AttributeValueMatches(definition, &adminv1.AttributeValue{Value: &adminv1.AttributeValue_EnumValue{EnumValue: "unapproved"}}) {
		t.Fatal("unknown enum member admitted")
	}
	if AttributeValueMatches(definition, &adminv1.AttributeValue{Value: &adminv1.AttributeValue_StringValue{StringValue: "canary"}}) {
		t.Fatal("string value bypassed enum type")
	}
	if AttributeValueMatches(nil, &adminv1.AttributeValue{Value: &adminv1.AttributeValue_IntValue{IntValue: 0}}) {
		t.Fatal("undeclared attribute admitted")
	}
}

// A retained device must still fit when the response carries maximum final
// counts, adoption references and a continuation cursor, including JSON escapes.
func TestImpactRowBudgetReservesFullResponseMetadata(t *testing.T) {
	for _, test := range []struct {
		name     string
		hostname string
		capacity bool
	}{
		{name: "large reviewable row", hostname: strings.Repeat("x", maxDocumentBytes/2)},
		{name: "metadata pushes row over ceiling", hostname: strings.Repeat("x", maxDocumentBytes-1024), capacity: true},
		{name: "JSON escaping exceeds ceiling", hostname: strings.Repeat("\x00", maxDocumentBytes/6), capacity: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			envelope := impactEnvelope(nil, 0, &adminv1.PreviewTargetAssignmentImpactResponse{})
			budget, err := newImpactRowBudget(envelope)
			if err != nil {
				t.Fatal(err)
			}
			item := &adminv1.TargetAssignmentDeviceImpact{Hostname: test.hostname}
			err = budget.validate(item)
			if test.capacity {
				if !errors.Is(err, ErrCapacity) {
					t.Fatalf("unreviewable impact row accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			envelope.Devices = []*adminv1.TargetAssignmentDeviceImpact{item}
			if err := ValidateResponse(envelope); err != nil {
				t.Fatalf("accepted impact row cannot be reviewed with full metadata: %v", err)
			}
		})
	}
}
