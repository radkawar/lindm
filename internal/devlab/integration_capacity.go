package devlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// AwaitIntegrationCapacity reserves headroom operationally, not transactionally:
// owned fixtures can still connect after this sample. The caller holds the host
// integration lock so integration suites cannot simultaneously pass admission.
func AwaitIntegrationCapacity(ctx context.Context, root string, log io.Writer) error {
	const minimumFree = 60
	lastReason := ""
	for {
		free, err := integrationFreeConnections(ctx, FixturePath(root))
		var pgErr *pgconn.PgError
		if err != nil && (!errors.As(err, &pgErr) || pgErr.Code != "53300") {
			return fmt.Errorf("integration database capacity: %w", err)
		}
		if err == nil && free >= minimumFree {
			return nil
		}
		reason := fmt.Sprintf("%d free PostgreSQL connection slots; need at least %d", free, minimumFree)
		if err != nil {
			reason = "PostgreSQL connection slots exhausted; need at least 60 free"
		}
		if reason != lastReason {
			_, _ = fmt.Fprintf(log, "test-integration: waiting for database capacity: %s\n", reason)
			lastReason = reason
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("integration database capacity: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func integrationFreeConnections(ctx context.Context, dir string) (free int, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := databaseConnection(ctx, dir, "migration-database-url")
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, conn.Close(ctx)) }()
	err = conn.QueryRow(ctx, "SELECT current_setting('max_connections')::integer - count(*) FROM pg_catalog.pg_stat_activity").Scan(&free)
	return free, err
}
