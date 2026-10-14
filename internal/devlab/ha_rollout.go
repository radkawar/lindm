// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
)

// HARolloutEvidence is a read-only snapshot of durable rollout effects. Health
// in this lane is explicitly fixture-seeded, not evidence of native execution.
type HARolloutEvidence struct {
	ID       string             `json:"id"`
	Creator  string             `json:"creator"`
	Revision int64              `json:"revision"`
	Ring     int32              `json:"ring"`
	Paused   bool               `json:"paused"`
	Reason   string             `json:"reason"`
	Stages   []HARolloutStage   `json:"stages"`
	Events   []HARolloutEvent   `json:"events"`
	Audits   []HARolloutAudit   `json:"audits"`
	Receipts []HARolloutReceipt `json:"receipts"`
}

// HARolloutStage retains the real database-clock start and frozen cohort size.
type HARolloutStage struct {
	Ring     int32     `json:"ring"`
	Started  time.Time `json:"started"`
	Selected int32     `json:"selected"`
}

// HARolloutEvent records a committed transition, including its acting principal.
type HARolloutEvent struct {
	ID       string    `json:"id"`
	Revision int64     `json:"revision"`
	Actor    string    `json:"actor"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
}

// HARolloutAudit preserves the independent audit of each automatic transition.
type HARolloutAudit struct {
	ID      string    `json:"id"`
	Actor   string    `json:"actor"`
	Reason  string    `json:"reason"`
	Context string    `json:"context"`
	At      time.Time `json:"at"`
}

// HARolloutReceipt is decoded from the actual stored idempotent response bytes.
type HARolloutReceipt struct {
	Request  string `json:"request"`
	Actor    string `json:"actor"`
	Ring     uint32 `json:"ring"`
	Revision uint64 `json:"revision"`
}

func (f *AuthorityFixture) haRolloutConnection(ctx context.Context) (*pgx.Conn, error) {
	if err := f.requireHA(); err != nil {
		return nil, err
	}
	if f.database == nil || !f.database.created || f.DatabaseName != f.database.name {
		return nil, errors.New("HA rollout evidence requires the owned database")
	}
	cfg, err := f.ha.adminConfig(0)
	if err != nil {
		return nil, err
	}
	cfg.Database = f.DatabaseName
	cfg.RuntimeParams["statement_timeout"] = "4000"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	return conn, profileError("connect HA rollout evidence", err)
}

// SeedHARolloutHealth supplies synthetic healthy proof for the current frozen
// cohort, tied to real current assignment heads and generations. It never edits
// stages, soak clocks, events, receipts or audit rows. Authenticated device loops
// still provide availability. This is a promotion/HA fixture, not a native gate.
func (f *AuthorityFixture) SeedHARolloutHealth(ctx context.Context, id string, ring int32) (seeded time.Time, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := f.haRolloutConnection(ctx)
	if err != nil {
		return seeded, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeProfileConnection(conn)) }()
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		var current, selected int32
		var paused bool
		if err := tx.QueryRow(ctx, `SELECT ring_index, paused FROM resource_rollouts WHERE id=$1 FOR UPDATE`, id).Scan(&current, &paused); err != nil {
			return err
		}
		if current != ring || paused {
			return errors.New("rollout changed before fixture health seed")
		}
		if err := tx.QueryRow(ctx, `SELECT selected_count, clock_timestamp() FROM resource_rollout_stages WHERE rollout_id=$1 AND ring_index=$2`, id, ring).Scan(&selected, &seeded); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE resource_rollout_members m SET health=1, received_at=$3,
health_valid_until=$3::timestamptz+interval '10 minutes', evidence_assignment_id=h.assignment_id
FROM devices d JOIN resource_assignment_heads h ON h.generation_id=d.current_generation_id
WHERE m.rollout_id=$1 AND m.ring_index=$2 AND m.membership=1
AND d.id=m.device_id AND d.current_generation_id=m.generation_id AND d.state='active'`, id, ring, seeded)
		if err != nil {
			return err
		}
		if selected < 1 || tag.RowsAffected() != int64(selected) {
			return errors.New("fixture cohort lacks current assignment heads")
		}
		return nil
	})
	return seeded, profileError("seed HA rollout health", err)
}

// ReadHARolloutEvidence reads one repeatable-read SQL snapshot; it does not call
// ListRollouts or any application mutation path.
func (f *AuthorityFixture) ReadHARolloutEvidence(ctx context.Context, id string) (e HARolloutEvidence, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := f.haRolloutConnection(ctx)
	if err != nil {
		return e, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeProfileConnection(conn)) }()
	e.ID = id
	err = pgx.BeginTxFunc(ctx, conn, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT creator_id::text, revision, ring_index, paused, pause_reason FROM resource_rollouts WHERE id=$1`, id).Scan(&e.Creator, &e.Revision, &e.Ring, &e.Paused, &e.Reason); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT ring_index, started_at, selected_count FROM resource_rollout_stages WHERE rollout_id=$1 ORDER BY ring_index LIMIT 17`, id)
		if err != nil {
			return err
		}
		e.Stages, err = pgx.CollectRows(rows, pgx.RowToStructByPos[HARolloutStage])
		if err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT id::text, revision, coalesce(actor_id::text,''), reason, created_at FROM resource_rollout_events WHERE rollout_id=$1 ORDER BY revision, id LIMIT 65`, id)
		if err != nil {
			return err
		}
		e.Events, err = pgx.CollectRows(rows, pgx.RowToStructByPos[HARolloutEvent])
		if err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT id::text, coalesce(actor_id::text,''), reason, coalesce(details->>'context',''), occurred_at FROM audit_events WHERE resource_id=$1 AND action='targeting.rollout.control' ORDER BY occurred_at, id LIMIT 65`, id)
		if err != nil {
			return err
		}
		e.Audits, err = pgx.CollectRows(rows, pgx.RowToStructByPos[HARolloutAudit])
		if err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT request_id::text, actor_id::text, response FROM targeting_requests WHERE actor_id=$1 AND method='targeting.rollout.control' ORDER BY request_id LIMIT 65`, e.Creator)
		if err != nil {
			return err
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			count++
			var receipt HARolloutReceipt
			var response []byte
			if err := rows.Scan(&receipt.Request, &receipt.Actor, &response); err != nil {
				return err
			}
			state, err := decodeHARolloutReceipt(response)
			if err != nil {
				return err
			}
			if state.GetRollout().GetRolloutId() == id {
				receipt.Ring, receipt.Revision = state.GetRingIndex(), state.GetRevision()
				e.Receipts = append(e.Receipts, receipt)
			}
		}
		if count > 64 || len(e.Events) > 64 || len(e.Audits) > 64 || len(e.Stages) > 16 {
			return errors.New("HA rollout evidence exceeds bounded snapshot")
		}
		return rows.Err()
	})
	return e, profileError("read HA rollout evidence", err)
}

func decodeHARolloutReceipt(data []byte) (*adminv1.RolloutState, error) {
	response := new(adminv1.ControlRolloutResponse)
	if err := proto.Unmarshal(data, response); err != nil {
		return nil, fmt.Errorf("decode rollout receipt: %w", err)
	}
	state := response.GetRollout()
	if state == nil || state.GetRevision() == 0 || state.GetRollout() == nil {
		return nil, errors.New("rollout receipt lacks committed state")
	}
	if _, err := uuid.Parse(state.GetRollout().GetRolloutId()); err != nil {
		return nil, errors.New("rollout receipt lacks campaign identity")
	}
	return state, nil
}
