// SPDX-License-Identifier: Apache-2.0

package targeting

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/targeting/targetingdb"
)

// Targeting admits only the inventory filter's string-keyed typed attribute map.
// encoded deterministically orders its keys before request and snapshot hashing;
// unknown fields remain rejected at every level, including each map value.
func validateTargetingClosed(message protoreflect.Message) error {
	if len(message.GetUnknown()) != 0 {
		return ErrRejected
	}
	var err error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.IsMap():
			if field.FullName() != "lindm.admin.v1.DeviceFilter.attributes" {
				err = ErrRejected
				return false
			}
			value.Map().Range(func(_ protoreflect.MapKey, value protoreflect.Value) bool {
				err = validateTargetingClosed(value.Message())
				return err == nil
			})
		case field.Message() == nil:
			return true
		case field.IsList():
			list := value.List()
			for i := range list.Len() {
				if err = validateTargetingClosed(list.Get(i).Message()); err != nil {
					return false
				}
			}
		default:
			err = validateTargetingClosed(value.Message())
		}
		return err == nil
	})
	return err
}

// AttributeValueMatches is the shared inventory metadata/filter semantic check.
// Serialized field bounds remain in the existing AttributeValue/Definition schema.
func AttributeValueMatches(definition *adminv1.AttributeDefinition, value *adminv1.AttributeValue) bool {
	if definition == nil || value == nil {
		return false
	}
	var kind adminv1.AttributeType
	switch value.GetValue().(type) {
	case *adminv1.AttributeValue_StringValue:
		kind = adminv1.AttributeType_ATTRIBUTE_TYPE_STRING
	case *adminv1.AttributeValue_IntValue:
		kind = adminv1.AttributeType_ATTRIBUTE_TYPE_INT
	case *adminv1.AttributeValue_BoolValue:
		kind = adminv1.AttributeType_ATTRIBUTE_TYPE_BOOL
	case *adminv1.AttributeValue_EnumValue:
		kind = adminv1.AttributeType_ATTRIBUTE_TYPE_ENUM
	default:
		return false
	}
	return kind == definition.GetType() && (kind != adminv1.AttributeType_ATTRIBUTE_TYPE_ENUM || slices.Contains(definition.GetEnumValues(), value.GetEnumValue()))
}

// Definition bytes are included in the input revision vector, including a missing
// definition marker. Incompatible current semantics yield UNKNOWN for an existing
// dynamic group, not a silent negative predicate or removal of its memberships.
func expressionDefinitions(ctx context.Context, q *targetingdb.Queries, expression *adminv1.TargetExpression) (map[string][]byte, bool, error) {
	definitions := make(map[string][]byte)
	decoded := make(map[string]*adminv1.AttributeDefinition)
	valid := true
	for _, node := range expression.Nodes {
		filter := node.GetPredicate()
		if filter == nil {
			continue
		}
		for key, value := range filter.Attributes {
			definition, known := decoded[key]
			if !known {
				encoded, err := q.GetTargetAttributeDefinition(ctx, key)
				if errors.Is(err, pgx.ErrNoRows) {
					definitions[key] = nil
					decoded[key] = nil
					valid = false
					continue
				}
				if err != nil {
					return nil, false, err
				}
				definition = new(adminv1.AttributeDefinition)
				if err := proto.Unmarshal(encoded, definition); err != nil {
					return nil, false, err
				}
				definitions[key] = encoded
				decoded[key] = definition
			}
			if !AttributeValueMatches(definition, value) {
				valid = false
			}
		}
	}
	return definitions, valid, nil
}
