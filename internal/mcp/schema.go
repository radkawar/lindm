package mcp

import (
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// messageSchema describes protobuf JSON shape; the existing Connect validation
// remains the only authority for field bounds, cross-field rules and authorization.
func messageSchema(message protoreflect.MessageDescriptor) map[string]any {
	definitions := make(map[string]map[string]any)
	schemaMessage(message, definitions)
	root := make(map[string]any)
	for key, value := range definitions[string(message.FullName())] {
		root[key] = value
	}
	root["$defs"] = definitions
	return root
}

func schemaMessage(message protoreflect.MessageDescriptor, definitions map[string]map[string]any) map[string]any {
	name := string(message.FullName())
	if name == "google.protobuf.Timestamp" || name == "google.protobuf.Duration" {
		return map[string]any{"type": "string"}
	}
	if _, exists := definitions[name]; exists {
		return map[string]any{"$ref": "#/$defs/" + name}
	}
	properties := make(map[string]any)
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	definitions[name] = schema
	for i := range message.Fields().Len() {
		field := message.Fields().Get(i)
		// The restart tool accepts only its one safe action and no approval reuse.
		if name == "lindm.admin.v1.CreateDeviceActionRequest" && field.Name() == "approval_id" {
			continue
		}
		if name == "lindm.agent.v1.DeviceActionSpec" && field.Name() != "restart" {
			continue
		}
		shape := schemaField(field, definitions)
		if field.IsMap() {
			shape = map[string]any{"type": "object", "additionalProperties": schemaField(field.MapValue(), definitions)}
		} else if field.IsList() {
			shape = map[string]any{"type": "array", "items": shape}
		}
		properties[field.JSONName()] = shape
	}
	return map[string]any{"$ref": "#/$defs/" + name}
}

func schemaField(field protoreflect.FieldDescriptor, definitions map[string]map[string]any) map[string]any {
	switch field.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return schemaMessage(field.Message(), definitions)
	case protoreflect.BoolKind:
		return map[string]any{"type": "boolean"}
	case protoreflect.StringKind:
		return map[string]any{"type": "string"}
	case protoreflect.BytesKind:
		return map[string]any{"type": "string", "contentEncoding": "base64"}
	case protoreflect.EnumKind:
		values := make([]string, field.Enum().Values().Len())
		for i := range values {
			values[i] = string(field.Enum().Values().Get(i).Name())
		}
		return map[string]any{"type": "string", "enum": values}
	case protoreflect.Int64Kind, protoreflect.Uint64Kind, protoreflect.Sint64Kind, protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind:
		return map[string]any{"type": []string{"string", "integer"}, "description": "Protobuf JSON decimal integer; strings preserve precision."}
	default:
		return map[string]any{"type": "number", "description": strings.ToLower(field.Kind().String())}
	}
}

func protoUint(value uint32) protoreflect.Value { return protoreflect.ValueOfUint32(value) }
