package device

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"lindm/internal/rpcreason"
)

func invalid(reason string) error {
	return rpcreason.Error(connect.CodeInvalidArgument, reason)
}

func mapErr(err error) error {
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
			return invalid("constraint")
		case "23505":
			return rpcreason.Error(connect.CodeAborted, "conflict")
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return rpcreason.Error(connect.CodeInternal, "internal")
	}
	return rpcreason.Error(connect.CodeInternal, "internal")
}
