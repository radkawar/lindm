// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"context"
	"crypto/sha256"
	"slices"
	"time"

	"lindm/internal/auditkind"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// Metadata and definitions share a catalog lock so a concurrent definition
// change cannot invalidate a value admitted against the previous definition.
func (s *Service) inventoryMutation(ctx context.Context, message proto.Message, method string, kind auditkind.Kind, resource, reason string, requestID uuid.UUID, deviceID *uuid.UUID, apply func(context.Context, *devicedb.Queries, identity.Principal) error) error {
	actor, err := s.Require(ctx, identity.PermissionManageInventory)
	if err != nil {
		return err
	}
	if s.Identity == nil {
		return rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	approval, err := s.Identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageInventory)
	if err != nil {
		return core.ExecutionError(err)
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.Identity.LockAuthorization(ctx, tx, approval, identity.PermissionManageInventory); err != nil {
		return core.ExecutionError(err)
	}
	authorized := approval.Principal()
	q := devicedb.New(tx)
	if err := q.LockInventoryMetadata(ctx); err != nil {
		return err
	}
	if deviceID != nil {
		if _, err := core.LockMutableDevice(ctx, q, authorized, identity.PermissionManageInventory, *deviceID); err != nil {
			return err
		}
	} else if err := core.RequireUnrestrictedPrincipal(authorized, identity.PermissionManageInventory); err != nil {
		return err
	}
	_, owned, err := s.BeginAdminRequest(ctx, q, actor.ID, method, requestID, digest[:])
	if err != nil {
		return err
	}
	if owned {
		if err := apply(ctx, q, authorized); err != nil {
			return err
		}
		var audit error
		if deviceID != nil {
			audit = core.DeviceAudit(ctx, q, &actor.ID, kind, resource, *deviceID, reason)
		} else {
			audit = core.InsertAudit(ctx, q, &actor.ID, kind, resource, reason)
		}
		if audit != nil {
			return audit
		}
		id := uuid.Nil
		if deviceID != nil {
			id = *deviceID
		}
		if err := core.CompleteAdmin(ctx, q, actor.ID, method, requestID, uuid.Nil, id, time.Unix(0, 0).UTC()); err != nil {
			return err
		}
	}
	if err := s.Identity.LockAuthorization(ctx, tx, approval, identity.PermissionManageInventory); err != nil {
		return core.ExecutionError(err)
	}
	return tx.Commit(ctx)
}

func (s *Service) SetDeviceMetadata(ctx context.Context, req *connect.Request[adminv1.SetDeviceMetadataRequest]) (*connect.Response[adminv1.SetDeviceMetadataResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionManageInventory); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_metadata")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	id, _ := uuid.Parse(req.Msg.GetDeviceId())
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	metadata := req.Msg.GetMetadata()
	err := s.inventoryMutation(ctx, req.Msg, "SetDeviceMetadata", auditkind.InventorySetDeviceMetadata, id.String(), req.Msg.GetReason(), requestID, &id, func(ctx context.Context, q *devicedb.Queries, authorized identity.Principal) error {
		labels, err := q.ListDeviceLabels(ctx, id)
		if err != nil {
			return err
		}
		// Labels participate in authorization scope. Inventory writers may edit
		// metadata, but only access administrators can change those scope inputs.
		if !sameInventoryLabels(labels, metadata.GetLabels()) {
			if !identity.Authorize(authorized, identity.PermissionManageAccounts) {
				return rpcreason.Error(connect.CodePermissionDenied, "permission_denied")
			}
			if err := core.RequireUnrestrictedPrincipal(authorized, identity.PermissionManageAccounts); err != nil {
				return err
			}
		}
		if err := core.ValidateAttributeValues(ctx, q, metadata.GetAttributes()); err != nil {
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
				return core.Invalid("owner_principal_unknown")
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
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.SetDeviceMetadataResponse{}), nil
}

func (s *Service) SetAttributeDefinition(ctx context.Context, req *connect.Request[adminv1.SetAttributeDefinitionRequest]) (*connect.Response[adminv1.SetAttributeDefinitionResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionManageInventory); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_attribute_definition")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	definition := req.Msg.GetDefinition()
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	err := s.inventoryMutation(ctx, req.Msg, "SetAttributeDefinition", auditkind.InventorySetAttributeDefinition, definition.GetKey(), req.Msg.GetReason(), requestID, nil, func(ctx context.Context, q *devicedb.Queries, _ identity.Principal) error {
		incompatible, err := q.AttributeDefinitionHasIncompatibleValues(ctx, devicedb.AttributeDefinitionHasIncompatibleValuesParams{
			Key: definition.GetKey(), ValueField: attributeValueField(definition.GetType()),
			IsEnum: definition.GetType() == adminv1.AttributeType_ATTRIBUTE_TYPE_ENUM, EnumValues: definition.GetEnumValues(),
		})
		if err != nil {
			return err
		}
		if incompatible {
			return rpcreason.Error(connect.CodeFailedPrecondition, "attribute_values_incompatible")
		}
		encoded, err := proto.Marshal(definition)
		if err != nil {
			return err
		}
		return q.SetAttributeDefinition(ctx, devicedb.SetAttributeDefinitionParams{Key: definition.GetKey(), Definition: encoded})
	})
	if err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.SetAttributeDefinitionResponse{}), nil
}

func (s *Service) ListAttributeDefinitions(ctx context.Context, req *connect.Request[adminv1.ListAttributeDefinitionsRequest]) (*connect.Response[adminv1.ListAttributeDefinitionsResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionReadFleet); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_argument")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	limit := core.PageLimit(req.Msg.GetPageSize())
	rows, err := devicedb.New(s.Pool).ListAttributeDefinitions(ctx, devicedb.ListAttributeDefinitionsParams{AfterKey: req.Msg.GetAfterKey(), RowLimit: limit + 1})
	if err != nil {
		return nil, core.MapErr(err)
	}
	response := &adminv1.ListAttributeDefinitionsResponse{}
	var budget core.ResponsePageBudget
	for _, row := range rows {
		if len(response.Definitions) == int(limit) {
			break
		}
		definition := new(adminv1.AttributeDefinition)
		if err := proto.Unmarshal(row.Definition, definition); err != nil {
			return nil, core.MapErr(core.ErrInternalState)
		}
		fits, err := budget.Take(definition)
		if err != nil {
			return nil, core.MapErr(err)
		}
		if !fits {
			break
		}
		response.Definitions = append(response.Definitions, definition)
	}
	if len(response.Definitions) < len(rows) {
		if len(response.Definitions) == 0 {
			return nil, core.MapErr(core.ErrInternalState)
		}
		response.NextAfterKey = response.Definitions[len(response.Definitions)-1].GetKey()
	}
	return core.NoStore(response), nil
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
