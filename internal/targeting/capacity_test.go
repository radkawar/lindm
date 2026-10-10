package targeting

import (
	"errors"
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
