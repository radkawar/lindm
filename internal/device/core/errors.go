// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"
	"log/slog"

	validate "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/policy"
	"lindm/internal/rpcreason"
)

func Invalid(reason string) error {
	return rpcreason.Error(connect.CodeInvalidArgument, reason)
}

func MapErr(err error) error {
	if err == nil {
		return nil
	}
	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		return err
	}
	if errors.Is(err, context.Canceled) {
		return rpcreason.Error(connect.CodeCanceled, "canceled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return rpcreason.Error(connect.CodeDeadlineExceeded, "deadline_exceeded")
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23514", "23502", "22001":
			// The device sees only "constraint"; name the violated schema
			// object (never the row's values) for the operator.
			slog.Warn("device database constraint violation", "code", pgErr.Code, "table", pgErr.TableName, "column", pgErr.ColumnName, "constraint", pgErr.ConstraintName)
			return Invalid("constraint")
		case "23505":
			return rpcreason.Error(connect.CodeAborted, "conflict")
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return rpcreason.Error(connect.CodeInternal, "internal")
	}
	return rpcreason.Error(connect.CodeInternal, "internal")
}

func ProfileError(err error) error {
	var setting *policy.SettingError
	switch {
	case errors.As(err, &setting):
		return settingViolation(setting)
	case errors.Is(err, policy.ErrProfileRejected):
		return Invalid("invalid_profile_request")
	case errors.Is(err, policy.ErrProfileConflict):
		return rpcreason.Error(connect.CodeAborted, "profile_revision_conflict")
	case errors.Is(err, policy.ErrProfileNotFound):
		return rpcreason.Error(connect.CodeNotFound, "profile_revision_not_found")
	case errors.Is(err, policy.ErrProfileCorrupt):
		return rpcreason.Error(connect.CodeFailedPrecondition, "profile_recovery_hold")
	case errors.Is(err, policy.ErrProfileCapacity):
		return rpcreason.Error(connect.CodeResourceExhausted, "profile_revision_capacity")
	default:
		return MapErr(err)
	}
}

// settingViolation reports the refused setting in the same buf.validate shape
// as schema violations, so clients locate it by its request field path.
func settingViolation(setting *policy.SettingError) error {
	failure := rpcreason.Error(connect.CodeInvalidArgument, policy.ErrSettingEmpty.Error())
	request := (&adminv1.PublishProfileRevisionRequest{}).ProtoReflect().Descriptor()
	spec := request.Fields().ByName("spec")
	resources := spec.Message().Fields().ByName("resources")
	desired := resources.Message().Fields().ByName("desired")
	path := []*validate.FieldPathElement{pathElement(spec), pathElement(resources), pathElement(desired), pathElement(setting.State)}
	path[1].Subscript = &validate.FieldPathElement_Index{Index: uint64(setting.Index)}
	detail, err := connect.NewErrorDetail(&validate.Violations{Violations: []*validate.Violation{{
		Field:   &validate.FieldPath{Elements: path},
		RuleId:  proto.String(policy.ErrSettingEmpty.Error()),
		Message: proto.String("setting has no effective content"),
	}}})
	if err != nil {
		return failure
	}
	failure.AddDetail(detail)
	return failure
}

func pathElement(field protoreflect.FieldDescriptor) *validate.FieldPathElement {
	return &validate.FieldPathElement{
		FieldNumber: proto.Int32(int32(field.Number())),
		FieldName:   proto.String(string(field.Name())),
		FieldType:   descriptorpb.FieldDescriptorProto_Type(field.Kind()).Enum(),
	}
}
