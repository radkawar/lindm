package core

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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
	switch {
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
