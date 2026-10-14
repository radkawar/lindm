// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"encoding/json"
	"net/http"
	"strings"
)

func patchSCIM(r *http.Request, document scimDocument) error {
	patch, err := readSCIMDocument(r)
	if err != nil {
		return err
	}
	schemas, ok := patch["schemas"].([]any)
	if !ok || len(schemas) != 1 || schemas[0] != scimMessages+"PatchOp" {
		return scimError(http.StatusBadRequest, "invalidSyntax", "PatchOp schema required")
	}
	operations, ok := scimAttribute(patch, "Operations").([]any)
	if !ok || len(operations) == 0 || len(operations) > 100 {
		return scimError(http.StatusBadRequest, "invalidValue", "PATCH requires 1 to 100 operations")
	}
	for _, raw := range operations {
		operation, ok := raw.(map[string]any)
		if !ok {
			return scimError(http.StatusBadRequest, "invalidSyntax", "Invalid PATCH operation")
		}
		op, _ := scimAttribute(operation, "op").(string)
		op = strings.ToLower(op)
		if op != "add" && op != "replace" && op != "remove" {
			return scimError(http.StatusBadRequest, "invalidSyntax", "Unsupported PATCH operation")
		}
		path, _ := scimAttribute(operation, "path").(string)
		value := scimAttribute(operation, "value")
		if path == "" {
			values, ok := value.(map[string]any)
			if !ok || op == "remove" {
				return scimError(http.StatusBadRequest, "noTarget", "An attribute path is required")
			}
			for key, item := range values {
				if err := scimPatchPath(document, op, key, item); err != nil {
					return err
				}
			}
		} else if err := scimPatchPath(document, op, path, value); err != nil {
			return err
		}
	}
	return nil
}

func scimAttribute(object map[string]any, name string) any {
	for key, value := range object {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return nil
}

func scimAttributeKey(object map[string]any, name string) string {
	for key := range object {
		if strings.EqualFold(key, name) {
			return key
		}
	}
	return name
}

func scimPatchPath(document scimDocument, op, path string, value any) error {
	if strings.HasPrefix(path, scimCore) {
		meta, _ := document["meta"].(map[string]any)
		kind, _ := meta["resourceType"].(string)
		prefix := scimCore + kind + ":"
		if !strings.HasPrefix(path, prefix) {
			return scimError(http.StatusBadRequest, "invalidPath", "Unsupported schema path")
		}
		path = strings.TrimPrefix(path, prefix)
	}
	root := path
	if index := strings.IndexAny(root, ".["); index >= 0 {
		root = root[:index]
	}
	if root == "" || strings.ContainsAny(path, "\r\n\x00") {
		return scimError(http.StatusBadRequest, "invalidPath", "Invalid attribute path")
	}
	for _, readonly := range []string{"id", "meta", "schemas", "groups"} {
		if strings.EqualFold(root, readonly) {
			return scimError(http.StatusBadRequest, "mutability", "Read-only attribute")
		}
	}
	if open := strings.IndexByte(path, '['); open >= 0 {
		close := strings.LastIndexByte(path, ']')
		if close <= open || path[:open] != root {
			return scimError(http.StatusBadRequest, "invalidPath", "Invalid value path")
		}
		filter := path[open+1 : close]
		parts := strings.SplitN(filter, " ", 3)
		var expected string
		if len(parts) != 3 || !strings.EqualFold(parts[1], "eq") || json.Unmarshal([]byte(parts[2]), &expected) != nil {
			return scimError(http.StatusBadRequest, "invalidFilter", "Value paths require string equality")
		}
		suffix := path[close+1:]
		if suffix != "" && (!strings.HasPrefix(suffix, ".") || strings.ContainsAny(suffix[1:], ".[]")) {
			return scimError(http.StatusBadRequest, "invalidPath", "Invalid subattribute path")
		}
		key := scimAttributeKey(document, root)
		values, ok := document[key].([]any)
		if !ok {
			return scimError(http.StatusBadRequest, "noTarget", "Value path did not match")
		}
		matched := false
		kept := make([]any, 0, len(values))
		for _, item := range values {
			object, ok := item.(map[string]any)
			actual, _ := scimAttribute(object, parts[0]).(string)
			if !ok || !strings.EqualFold(actual, expected) {
				kept = append(kept, item)
				continue
			}
			matched = true
			if suffix != "" {
				if err := scimPatchObject(object, op, suffix[1:], value); err != nil {
					return err
				}
				kept = append(kept, item)
			} else if op != "remove" {
				replacement, ok := value.(map[string]any)
				if !ok {
					return scimError(http.StatusBadRequest, "invalidValue", "Selected complex value requires an object")
				}
				if op == "add" {
					for name, field := range replacement {
						object[scimAttributeKey(object, name)] = field
					}
					kept = append(kept, object)
				} else {
					kept = append(kept, replacement)
				}
			}
		}
		if !matched {
			return scimError(http.StatusBadRequest, "noTarget", "Value path did not match")
		}
		document[key] = kept
		return nil
	}
	return scimPatchObject(document, op, path, value)
}

func scimPatchObject(object map[string]any, op, path string, value any) error {
	parts := strings.Split(path, ".")
	if len(parts) > 2 || strings.ContainsAny(path, "[]:") {
		return scimError(http.StatusBadRequest, "invalidPath", "Unsupported attribute path")
	}
	key := scimAttributeKey(object, parts[0])
	if len(parts) == 2 {
		if parts[1] == "" {
			return scimError(http.StatusBadRequest, "invalidPath", "Empty subattribute path")
		}
		child, ok := object[key].(map[string]any)
		if !ok {
			if op == "remove" {
				return scimError(http.StatusBadRequest, "noTarget", "Attribute does not exist")
			}
			if _, exists := object[key]; exists {
				return scimError(http.StatusBadRequest, "invalidPath", "Attribute is not complex")
			}
			child = make(map[string]any)
			object[key] = child
		}
		return scimPatchObject(child, op, parts[1], value)
	}
	if op == "remove" {
		if _, exists := object[key]; !exists {
			return scimError(http.StatusBadRequest, "noTarget", "Attribute does not exist")
		}
		delete(object, key)
		return nil
	}
	if value == nil {
		return scimError(http.StatusBadRequest, "invalidValue", "PATCH value is required")
	}
	if op == "add" {
		if current, ok := object[key].([]any); ok {
			additional, ok := value.([]any)
			if !ok || len(current)+len(additional) > scimMaxMembers {
				return scimError(http.StatusBadRequest, "invalidValue", "Invalid or oversized multi-valued attribute")
			}
			object[key] = append(current, additional...)
			return nil
		}
		if current, ok := object[key].(map[string]any); ok {
			additional, ok := value.(map[string]any)
			if !ok {
				return scimError(http.StatusBadRequest, "invalidValue", "Complex value required")
			}
			for name, field := range additional {
				current[scimAttributeKey(current, name)] = field
			}
			return nil
		}
	}
	object[key] = value
	return nil
}
