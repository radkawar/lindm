package device

import (
	"context"
	"crypto/sha256"
	"slices"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/targeting"
)

// Metadata and definitions share a catalog lock so a concurrent definition
// change cannot invalidate a value admitted against the previous definition.
func (s *Service) inventoryMutation(ctx context.Context, message proto.Message, method, resource, reason string, requestID uuid.UUID, deviceID *uuid.UUID, apply func(context.Context, *devicedb.Queries, identity.Principal) error) error {
	actor, err := s.require(ctx, identity.PermissionManageInventory)
	if err != nil {
		return err
	}
	if s.identity == nil {
		return rpcError(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	approval, err := s.identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageInventory)
	if err != nil {
		return executionError(err)
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionManageInventory); err != nil {
		return executionError(err)
	}
	authorized := approval.Principal()
	q := devicedb.New(tx)
	if err := q.LockInventoryMetadata(ctx); err != nil {
		return err
	}
	if deviceID != nil {
		if _, err := lockDeviceScope(ctx, q, authorized, identity.PermissionManageInventory, *deviceID); err != nil {
			return err
		}
	} else if err := requireUnrestrictedPrincipal(authorized, identity.PermissionManageInventory); err != nil {
		return err
	}
	_, owned, err := s.beginAdminRequest(ctx, q, actor.ID, method, requestID, digest[:])
	if err != nil {
		return err
	}
	if owned {
		if err := apply(ctx, q, authorized); err != nil {
			return err
		}
		if err := insertAudit(ctx, q, &actor.ID, "inventory."+method, resource, reason); err != nil {
			return err
		}
		id := uuid.Nil
		if deviceID != nil {
			id = *deviceID
		}
		if err := completeAdmin(ctx, q, actor.ID, method, requestID, uuid.Nil, id, time.Unix(0, 0).UTC()); err != nil {
			return err
		}
	}
	if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionManageInventory); err != nil {
		return executionError(err)
	}
	return tx.Commit(ctx)
}

func (s *Service) SetDeviceMetadata(ctx context.Context, req *connect.Request[adminv1.SetDeviceMetadataRequest]) (*connect.Response[adminv1.SetDeviceMetadataResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.require(ctx, identity.PermissionManageInventory); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_metadata")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	id, _ := uuid.Parse(req.Msg.GetDeviceId())
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	metadata := req.Msg.GetMetadata()
	err := s.inventoryMutation(ctx, req.Msg, "SetDeviceMetadata", id.String(), req.Msg.GetReason(), requestID, &id, func(ctx context.Context, q *devicedb.Queries, authorized identity.Principal) error {
		labels, err := q.ListDeviceLabels(ctx, id)
		if err != nil {
			return err
		}
		// Labels participate in authorization scope. Inventory writers may edit
		// metadata, but only access administrators can change those scope inputs.
		if !sameInventoryLabels(labels, metadata.GetLabels()) {
			if !identity.Authorize(authorized, identity.PermissionManageAccounts) {
				return rpcError(connect.CodePermissionDenied, "permission_denied")
			}
			if err := requireUnrestrictedPrincipal(authorized, identity.PermissionManageAccounts); err != nil {
				return err
			}
		}
		if err := validateAttributeValues(ctx, q, metadata.GetAttributes()); err != nil {
			return err
		}
		var owner *uuid.UUID
		if metadata.GetOwnerPrincipalId() != "" {
			value, _ := uuid.Parse(metadata.GetOwnerPrincipalId())
			found, err := q.InventoryOwnerExists(ctx, value)
			if err != nil {
				return err
			}
			if !found {
				return invalid("owner_principal_unknown")
			}
			owner = &value
		}
		encoded, err := protojson.Marshal(metadata)
		if err != nil {
			return err
		}
		if err := q.SetDeviceMetadata(ctx, devicedb.SetDeviceMetadataParams{ID: id, Metadata: encoded, OwnerPrincipalID: owner}); err != nil {
			return err
		}
		if err := q.DeleteDeviceLabels(ctx, id); err != nil {
			return err
		}
		return q.InsertDeviceLabels(ctx, devicedb.InsertDeviceLabelsParams{DeviceID: id, Labels: metadata.GetLabels()})
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.SetDeviceMetadataResponse{}), nil
}

func (s *Service) SetAttributeDefinition(ctx context.Context, req *connect.Request[adminv1.SetAttributeDefinitionRequest]) (*connect.Response[adminv1.SetAttributeDefinitionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.requireUnrestricted(ctx, identity.PermissionManageInventory); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_attribute_definition")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	definition := req.Msg.GetDefinition()
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	err := s.inventoryMutation(ctx, req.Msg, "SetAttributeDefinition", definition.GetKey(), req.Msg.GetReason(), requestID, nil, func(ctx context.Context, q *devicedb.Queries, _ identity.Principal) error {
		incompatible, err := q.AttributeDefinitionHasIncompatibleValues(ctx, devicedb.AttributeDefinitionHasIncompatibleValuesParams{
			Key: definition.GetKey(), ValueField: attributeValueField(definition.GetType()),
			IsEnum: definition.GetType() == adminv1.AttributeType_ATTRIBUTE_TYPE_ENUM, EnumValues: definition.GetEnumValues(),
		})
		if err != nil {
			return err
		}
		if incompatible {
			return rpcError(connect.CodeFailedPrecondition, "attribute_values_incompatible")
		}
		encoded, err := proto.Marshal(definition)
		if err != nil {
			return err
		}
		return q.SetAttributeDefinition(ctx, devicedb.SetAttributeDefinitionParams{Key: definition.GetKey(), Definition: encoded})
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.SetAttributeDefinitionResponse{}), nil
}

func (s *Service) ListAttributeDefinitions(ctx context.Context, req *connect.Request[adminv1.ListAttributeDefinitionsRequest]) (*connect.Response[adminv1.ListAttributeDefinitionsResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.requireUnrestricted(ctx, identity.PermissionReadFleet); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_argument")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	limit := pageLimit(req.Msg.GetPageSize())
	rows, err := devicedb.New(s.pool).ListAttributeDefinitions(ctx, devicedb.ListAttributeDefinitionsParams{AfterKey: req.Msg.GetAfterKey(), RowLimit: limit + 1})
	if err != nil {
		return nil, mapErr(err)
	}
	response := &adminv1.ListAttributeDefinitionsResponse{}
	var budget responsePageBudget
	for _, row := range rows {
		if len(response.Definitions) == int(limit) {
			break
		}
		definition := new(adminv1.AttributeDefinition)
		if err := proto.Unmarshal(row.Definition, definition); err != nil {
			return nil, mapErr(errInternalState)
		}
		fits, err := budget.take(definition)
		if err != nil {
			return nil, mapErr(err)
		}
		if !fits {
			break
		}
		response.Definitions = append(response.Definitions, definition)
	}
	if len(response.Definitions) < len(rows) {
		if len(response.Definitions) == 0 {
			return nil, mapErr(errInternalState)
		}
		response.NextAfterKey = response.Definitions[len(response.Definitions)-1].GetKey()
	}
	return noStore(response), nil
}

func validateAttributeValues(ctx context.Context, q *devicedb.Queries, attributes map[string]*adminv1.AttributeValue) error {
	for key, value := range attributes {
		encoded, err := q.GetAttributeDefinition(ctx, key)
		if err == pgx.ErrNoRows {
			return invalid("attribute_key_unknown")
		}
		if err != nil {
			return err
		}
		definition := new(adminv1.AttributeDefinition)
		if err := proto.Unmarshal(encoded, definition); err != nil {
			return errInternalState
		}
		if !targeting.AttributeValueMatches(definition, value) {
			return invalid("attribute_type_mismatch")
		}
	}
	return nil
}

func attributeValueField(kind adminv1.AttributeType) string {
	switch kind {
	case adminv1.AttributeType_ATTRIBUTE_TYPE_STRING:
		return "stringValue"
	case adminv1.AttributeType_ATTRIBUTE_TYPE_INT:
		return "intValue"
	case adminv1.AttributeType_ATTRIBUTE_TYPE_BOOL:
		return "boolValue"
	case adminv1.AttributeType_ATTRIBUTE_TYPE_ENUM:
		return "enumValue"
	default:
		return ""
	}
}

func sameInventoryLabels(current, desired []string) bool {
	if len(current) != len(desired) {
		return false
	}
	for _, label := range current {
		if !slices.Contains(desired, label) {
			return false
		}
	}
	return true
}
