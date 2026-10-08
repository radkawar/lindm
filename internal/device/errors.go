package device

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func rpcError(code connect.Code, reason string) error {
	err := connect.NewError(code, errors.New(reason))
	err.Meta().Set("Lindm-Reason", reason)
	return err
}

func invalid(reason string) error {
	return rpcError(connect.CodeInvalidArgument, reason)
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
		return rpcError(connect.CodeCanceled, "canceled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return rpcError(connect.CodeDeadlineExceeded, "deadline_exceeded")
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23514", "23502", "22001":
			return invalid("constraint")
		case "23505":
			return rpcError(connect.CodeAborted, "conflict")
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return rpcError(connect.CodeInternal, "internal")
	}
	return rpcError(connect.CodeInternal, "internal")
}
