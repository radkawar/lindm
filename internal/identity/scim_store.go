// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"lindm/internal/auditkind"
	"lindm/internal/identity/identitydb"
)

func (s *Service) renderSCIM(ctx context.Context, q *identitydb.Queries, row identitydb.ScimResource) (scimDocument, error) {
	var document scimDocument
	if err := json.Unmarshal(row.Document, &document); err != nil {
		return nil, err
	}
	document["id"] = row.ID.String()
	document["schemas"] = []any{scimCore + row.ResourceType}
	document["meta"] = map[string]any{
		"resourceType": row.ResourceType,
		"created":      row.CreatedAt.Time.UTC().Format(time.RFC3339Nano),
		"lastModified": row.ModifiedAt.Time.UTC().Format(time.RFC3339Nano),
		"version":      scimETag(row.Version),
		"location":     s.publicOrigin + scimBase + row.ResourceType + "s/" + row.ID.String(),
	}
	if row.ResourceType == "Group" {
		members, err := q.ListSCIMMembers(ctx, row.ID)
		if err != nil {
			return nil, err
		}
		if len(members) > scimMaxMembers {
			return nil, errStore
		}
		values := make([]any, 0, len(members))
		for _, member := range members {
			values = append(values, map[string]any{"value": member.ID.String(), "$ref": s.publicOrigin + scimBase + "Users/" + member.ID.String(), "type": "User"})
		}
		document["members"] = values
	}
	return document, nil
}

func (s *Service) createSCIM(ctx context.Context, q *identitydb.Queries, connectorID string, connector scimConnector, kind string, document scimDocument) (identitydb.ScimResource, error) {
	if err := validateSCIMDocument(document, kind, uuid.Nil); err != nil {
		return identitydb.ScimResource{}, err
	}
	externalID, _ := document["externalId"].(string)
	if externalID != "" {
		previous, err := q.GetSCIMResourceByExternalID(ctx, identitydb.GetSCIMResourceByExternalIDParams{ConnectorID: connectorID, ResourceType: kind, ExternalID: externalID})
		if err == nil {
			if !previous.Deleted {
				return identitydb.ScimResource{}, scimError(http.StatusConflict, "uniqueness", "externalId already exists")
			}
			// An authorized connector may reprovision exactly its configured immutable
			// identity. Reuse the durable row; deletion never erases the tombstone.
			return s.updateSCIM(ctx, q, connector, previous, document, false)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return identitydb.ScimResource{}, err
		}
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return identitydb.ScimResource{}, err
	}
	var principalID *uuid.UUID
	if kind == "User" {
		correlation, ok := connector.correlations[externalID]
		if !ok {
			return identitydb.ScimResource{}, scimError(http.StatusBadRequest, "invalidValue", "externalId lacks a configured immutable correlation")
		}
		principal, err := q.UpsertPrincipal(ctx, identitydb.UpsertPrincipalParams{ID: id, Issuer: correlation.issuer, Subject: correlation.subject})
		if err != nil {
			return identitydb.ScimResource{}, err
		}
		principalID = &principal.ID
	}
	members, _ := document["members"].([]any)
	delete(document, "members")
	encoded, err := json.Marshal(document)
	if err != nil {
		return identitydb.ScimResource{}, err
	}
	username, _ := document["userName"].(string)
	row, err := q.InsertSCIMResource(ctx, identitydb.InsertSCIMResourceParams{ID: id, ConnectorID: connectorID, ResourceType: kind, ExternalID: externalID, UserName: username, PrincipalID: principalID, Document: encoded})
	if err != nil {
		return identitydb.ScimResource{}, err
	}
	if kind == "User" {
		active, _ := document["active"].(bool)
		err = s.scimLifecycle(ctx, q, *principalID, active)
	} else {
		err = replaceSCIMMembers(ctx, q, row, members)
	}
	if err != nil {
		return identitydb.ScimResource{}, err
	}
	return row, s.insertSystemAudit(ctx, q, nil, auditkind.IdentitySCIMCreated, "scim/"+connectorID+"/"+id.String(), kind)
}

func (s *Service) updateSCIM(ctx context.Context, q *identitydb.Queries, connector scimConnector, row identitydb.ScimResource, document scimDocument, deleted bool) (identitydb.ScimResource, error) {
	if err := validateSCIMDocument(document, row.ResourceType, row.ID); err != nil {
		return identitydb.ScimResource{}, err
	}
	externalID, _ := document["externalId"].(string)
	username, _ := document["userName"].(string)
	if row.ResourceType == "User" {
		if externalID != row.ExternalID {
			return identitydb.ScimResource{}, scimError(http.StatusBadRequest, "mutability", "User externalId is an immutable configured provider ID")
		}
		correlation, ok := connector.correlations[externalID]
		if !ok || row.PrincipalID == nil {
			return identitydb.ScimResource{}, scimError(http.StatusForbidden, "", "Immutable correlation is no longer configured")
		}
		principal, err := q.GetPrincipalForUpdate(ctx, *row.PrincipalID)
		if err != nil {
			return identitydb.ScimResource{}, err
		}
		if principal.Issuer != correlation.issuer || principal.Subject != correlation.subject {
			return identitydb.ScimResource{}, scimError(http.StatusConflict, "uniqueness", "Immutable correlation conflict")
		}
		var previous scimDocument
		if err := json.Unmarshal(row.Document, &previous); err != nil {
			return identitydb.ScimResource{}, err
		}
		active, _ := document["active"].(bool)
		if deleted {
			active = false
			document["active"] = false
		}
		if deleted || row.Deleted || previous["active"] != active {
			if err := s.scimLifecycle(ctx, q, principal.ID, active); err != nil {
				return identitydb.ScimResource{}, err
			}
		}
		if deleted {
			if err := q.RemoveSCIMUserMemberships(ctx, row.ID); err != nil {
				return identitydb.ScimResource{}, err
			}
		}
	} else {
		members, _ := document["members"].([]any)
		if deleted {
			members = nil
		}
		if err := replaceSCIMMembers(ctx, q, row, members); err != nil {
			return identitydb.ScimResource{}, err
		}
	}
	delete(document, "members")
	encoded, err := json.Marshal(document)
	if err != nil {
		return identitydb.ScimResource{}, err
	}
	updated, err := q.UpdateSCIMResource(ctx, identitydb.UpdateSCIMResourceParams{ConnectorID: row.ConnectorID, ResourceType: row.ResourceType, ID: row.ID, Document: encoded, UserName: username, ExternalID: externalID, Deleted: deleted})
	if err != nil {
		return identitydb.ScimResource{}, err
	}
	action := auditkind.IdentitySCIMUpdated
	if deleted {
		action = auditkind.IdentitySCIMDeleted
	}
	return updated, s.insertSystemAudit(ctx, q, nil, action, "scim/"+row.ConnectorID+"/"+row.ID.String(), row.ResourceType)
}

// The principal lock is shared with login, observations and worker dispatch.
// Clearing snapshots and advancing the version never supplies positive authority;
// reactivation needs a new authoritative read acquired after this transaction.
func (s *Service) scimLifecycle(ctx context.Context, q *identitydb.Queries, id uuid.UUID, active bool) error {
	if _, err := q.GetPrincipalForUpdate(ctx, id); err != nil {
		return err
	}
	if err := q.SetSCIMPrincipalLifecycle(ctx, identitydb.SetSCIMPrincipalLifecycleParams{ID: id, Active: active}); err != nil {
		return err
	}
	if err := q.ClearSCIMLineageObservation(ctx, id); err != nil {
		return err
	}
	if err := q.DeletePrincipalGroups(ctx, id); err != nil {
		return err
	}
	if _, err := s.revokePrincipalCredentials(ctx, q, id); err != nil {
		return err
	}
	reason := "deactivated"
	if active {
		reason = "reactivated; authoritative refresh required"
	}
	return s.insertSystemAudit(ctx, q, &id, auditkind.IdentitySCIMLifecycle, principalResource(id), reason)
}

func replaceSCIMMembers(ctx context.Context, q *identitydb.Queries, group identitydb.ScimResource, members []any) error {
	if len(members) > scimMaxMembers {
		return scimError(http.StatusBadRequest, "tooMany", "Group membership exceeds 1000 members")
	}
	if err := q.ClearSCIMMembers(ctx, group.ID); err != nil {
		return err
	}
	seen := make(map[uuid.UUID]struct{}, len(members))
	for _, value := range members {
		member, ok := value.(map[string]any)
		if !ok {
			return scimError(http.StatusBadRequest, "invalidValue", "Invalid member")
		}
		text, _ := member["value"].(string)
		id, err := uuid.Parse(text)
		if err != nil {
			return scimError(http.StatusBadRequest, "invalidValue", "Member value must be a provisioned User id")
		}
		if memberType, ok := member["type"]; ok && memberType != "User" {
			return scimError(http.StatusBadRequest, "invalidValue", "Only User members are supported")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		user, err := q.GetSCIMResource(ctx, identitydb.GetSCIMResourceParams{ConnectorID: group.ConnectorID, ResourceType: "User", ID: id})
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && user.Deleted) {
			return scimError(http.StatusBadRequest, "invalidValue", "Member is not an existing User in this connector")
		}
		if err != nil {
			return err
		}
		if err := q.InsertSCIMMember(ctx, identitydb.InsertSCIMMemberParams{ConnectorID: group.ConnectorID, GroupID: group.ID, UserID: id}); err != nil {
			return err
		}
	}
	return nil
}

func validateSCIMDocument(document scimDocument, kind string, id uuid.UUID) error {
	attributes := scimAttributes(kind)
	for key, value := range document {
		canonical := ""
		for name := range attributes {
			if strings.EqualFold(key, name) {
				canonical = name
				break
			}
		}
		if canonical == "" {
			return scimError(http.StatusBadRequest, "invalidValue", "Unknown or unsupported attribute: "+key)
		}
		if key != canonical {
			if _, exists := document[canonical]; exists {
				return scimError(http.StatusBadRequest, "invalidSyntax", "Duplicate attribute")
			}
			delete(document, key)
			document[canonical] = value
		}
		if value == nil {
			delete(document, canonical)
			continue
		}
		switch attributes[canonical] {
		case "string":
			text, ok := value.(string)
			if !ok || !boundedText(text, 0, 256) {
				return scimError(http.StatusBadRequest, "invalidValue", "Invalid string attribute: "+canonical)
			}
		case "boolean":
			if _, ok := value.(bool); !ok {
				return scimError(http.StatusBadRequest, "invalidValue", "Invalid boolean attribute")
			}
		case "complex":
			if _, ok := value.(map[string]any); !ok {
				return scimError(http.StatusBadRequest, "invalidValue", "Invalid complex attribute")
			}
		case "multi":
			values, ok := value.([]any)
			if !ok || len(values) > scimMaxMembers {
				return scimError(http.StatusBadRequest, "invalidValue", "Invalid or oversized multi-valued attribute")
			}
			for _, item := range values {
				if _, ok := item.(map[string]any); !ok {
					return scimError(http.StatusBadRequest, "invalidValue", "Invalid multi-valued entry")
				}
			}
		}
	}
	if value, ok := document["id"]; ok && value != id.String() {
		return scimError(http.StatusBadRequest, "mutability", "id is server assigned and immutable")
	}
	delete(document, "id")
	delete(document, "meta")
	if schemas, ok := document["schemas"].([]any); !ok || len(schemas) != 1 || schemas[0] != scimCore+kind {
		return scimError(http.StatusBadRequest, "invalidValue", "Exactly the supported core schema is required")
	}
	if kind == "User" {
		for _, name := range []string{"userName", "externalId"} {
			value, _ := document[name].(string)
			if !boundedText(value, 1, 256) {
				return scimError(http.StatusBadRequest, "invalidValue", name+" is required")
			}
		}
		if _, ok := document["active"]; !ok {
			document["active"] = true
		}
	} else if value, _ := document["displayName"].(string); value == "" {
		return scimError(http.StatusBadRequest, "invalidValue", "displayName is required")
	}
	return nil
}

func scimAttributes(kind string) map[string]string {
	attributes := map[string]string{"schemas": "schemas", "id": "string", "meta": "complex", "externalId": "string", "displayName": "string"}
	if kind == "Group" {
		attributes["members"] = "multi"
		return attributes
	}
	for _, key := range []string{"userName", "nickName", "profileUrl", "title", "userType", "preferredLanguage", "locale", "timezone"} {
		attributes[key] = "string"
	}
	attributes["active"] = "boolean"
	attributes["name"] = "complex"
	for _, key := range []string{"emails", "phoneNumbers", "ims", "photos", "addresses", "entitlements", "roles", "x509Certificates"} {
		attributes[key] = "multi"
	}
	return attributes
}
