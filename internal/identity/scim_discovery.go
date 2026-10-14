// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"sort"
	"strings"
)

func scimDiscovery(path string) (any, bool) {
	if path == "ServiceProviderConfig" {
		return map[string]any{
			"schemas":               []string{scimCore + "ServiceProviderConfig"},
			"documentationUri":      "https://www.rfc-editor.org/rfc/rfc7644",
			"patch":                 map[string]any{"supported": true},
			"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
			"filter":                map[string]any{"supported": true, "maxResults": scimMaxPage},
			"changePassword":        map[string]any{"supported": false},
			"sort":                  map[string]any{"supported": false},
			"etag":                  map[string]any{"supported": true},
			"authenticationSchemes": []any{map[string]any{"type": "oauthbearertoken", "name": "Dedicated connector bearer", "description": "Hash-only credential scoped to one configured connector; provision and rotate through /auth/scim/credentials/rotate with unrestricted accounts.manage. PUT/PATCH/DELETE require the exact resource If-Match ETag. Membership is provisioning data, never authorization freshness or grants.", "primary": true}},
		}, true
	}
	if path == "ResourceTypes" {
		return scimDiscoveryList([]any{scimResourceType("User"), scimResourceType("Group")}), true
	}
	if strings.HasPrefix(path, "ResourceTypes/") {
		kind := strings.TrimPrefix(path, "ResourceTypes/")
		if kind == "User" || kind == "Group" {
			return scimResourceType(kind), true
		}
	}
	if path == "Schemas" {
		return scimDiscoveryList([]any{scimSchema("User"), scimSchema("Group")}), true
	}
	if strings.HasPrefix(path, "Schemas/"+scimCore) {
		kind := strings.TrimPrefix(path, "Schemas/"+scimCore)
		if kind == "User" || kind == "Group" {
			return scimSchema(kind), true
		}
	}
	return nil, false
}

func scimDiscoveryList(resources []any) any {
	return map[string]any{"schemas": []string{scimMessages + "ListResponse"}, "totalResults": len(resources), "startIndex": 1, "itemsPerPage": len(resources), "Resources": resources}
}

func scimResourceType(kind string) any {
	return map[string]any{"schemas": []string{scimCore + "ResourceType"}, "id": kind, "name": kind, "endpoint": "/" + kind + "s", "schema": scimCore + kind, "schemaExtensions": []any{}, "meta": map[string]any{"resourceType": "ResourceType", "location": scimBase + "ResourceTypes/" + kind}}
}

func scimSchema(kind string) any {
	definitions := scimAttributes(kind)
	names := make([]string, 0, len(definitions))
	for name := range definitions {
		if name != "schemas" && name != "meta" && name != "id" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	attributes := make([]any, 0, len(names))
	for _, name := range names {
		attributeType := definitions[name]
		multi := attributeType == "multi"
		if multi {
			attributeType = "complex"
		}
		attribute := scimSchemaAttribute(name, attributeType, multi)
		attribute["required"] = (kind == "User" && (name == "userName" || name == "externalId")) || (kind == "Group" && name == "displayName")
		if name == "externalId" && kind == "User" {
			attribute["mutability"] = "immutable"
			attribute["caseExact"] = true
			attribute["uniqueness"] = "server"
			attribute["description"] = "Exact configured immutable provider ID; never username or email correlation"
		}
		if name == "userName" {
			attribute["uniqueness"] = "server"
		}
		if attributeType == "complex" {
			fields := []string{"value", "display", "type", "primary"}
			switch name {
			case "name":
				fields = []string{"formatted", "familyName", "givenName", "middleName", "honorificPrefix", "honorificSuffix"}
			case "addresses":
				fields = []string{"formatted", "streetAddress", "locality", "region", "postalCode", "country", "type", "primary"}
			case "members":
				fields = []string{"value", "$ref", "type"}
			}
			subAttributes := make([]any, 0, len(fields))
			for _, field := range fields {
				fieldType := "string"
				if field == "primary" {
					fieldType = "boolean"
				}
				sub := scimSchemaAttribute(field, fieldType, false)
				if name == "members" {
					sub["caseExact"] = true
					if field == "value" {
						sub["required"] = true
					}
					if field == "type" {
						sub["canonicalValues"] = []string{"User"}
					}
				}
				subAttributes = append(subAttributes, sub)
			}
			attribute["subAttributes"] = subAttributes
		}
		attributes = append(attributes, attribute)
	}
	return map[string]any{"schemas": []string{scimCore + "Schema"}, "id": scimCore + kind, "name": kind, "description": "Connector-scoped " + kind + " provisioning; no directory grants or freshness", "attributes": attributes, "meta": map[string]any{"resourceType": "Schema", "location": scimBase + "Schemas/" + scimCore + kind}}
}

func scimSchemaAttribute(name, kind string, multi bool) map[string]any {
	return map[string]any{"name": name, "type": kind, "multiValued": multi, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"}
}
