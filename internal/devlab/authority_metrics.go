// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// AuthorityMetrics describes only the disposable fixture, never shared dev data.
// Connections count client backends only; autovacuum and other background work
// are separate. Active connections are an occupancy proxy, not acquire-queue depth.
type AuthorityMetrics struct {
	DatabaseBytes                int64
	Connections                  int
	ActiveConnections            int
	IdleConnections              int
	IdleInTransactionConnections int
	WaitingConnections           int
	AutovacuumWorkers            int
	OtherBackgroundBackends      int
	CPUClockTicks                uint64
	RSSBytes                     uint64
	PostgreSQLVersion            string
	PoolLimit                    int
}

// Measure reads process counters and PostgreSQL statistics without modifying data.
func (f *AuthorityFixture) Measure(ctx context.Context) (_ AuthorityMetrics, resultErr error) {
	var m AuthorityMetrics
	if f.closed || f.process == nil {
		return m, errors.New("authority fixture is not running")
	}
	cfg := f.database.admin.Copy()
	cfg.Database = f.DatabaseName
	cfg.RuntimeParams["application_name"] = authorityProfileApplication
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return m, err
	}
	defer func() { resultErr = errors.Join(resultErr, conn.Close(ctx)) }()
	err = conn.QueryRow(ctx, `SELECT pg_database_size(current_database()), version()`).Scan(&m.DatabaseBytes, &m.PostgreSQLVersion)
	if err != nil {
		return m, err
	}
	counts, err := readAuthorityConnectionCounts(ctx, conn)
	if err != nil {
		return m, err
	}
	m.Connections = counts.Connections
	m.ActiveConnections = counts.ActiveConnections
	m.IdleConnections = counts.IdleConnections
	m.IdleInTransactionConnections = counts.IdleInTransactionConnections
	m.WaitingConnections = counts.WaitingConnections
	m.AutovacuumWorkers = counts.AutovacuumWorkers
	m.OtherBackgroundBackends = counts.OtherBackgroundBackends
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", f.process.Pid()))
	if err != nil {
		return m, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return m, errors.New("invalid process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 22 {
		return m, errors.New("short process stat")
	}
	user, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return m, err
	}
	system, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return m, err
	}
	pages, err := strconv.ParseUint(fields[21], 10, 64)
	if err != nil {
		return m, err
	}
	m.CPUClockTicks = user + system
	m.RSSBytes = pages * uint64(os.Getpagesize())
	m.PoolLimit = 8
	return m, nil
}
