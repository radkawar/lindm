// Package auditfilter normalizes shared audit selections for SQL and cursor
// binding. Schema validation belongs to the RPC validators; category membership
// is captured by the database's audit_action_category function, except the
// human-actions view's bookkeeping exclusions, which come from auditkind.
package auditfilter

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "lindm/gen/lindm/audit/v1"
	"lindm/internal/auditkind"
)

// Selection is the normalized SQL input, not a second validation schema.
type Selection struct {
	Filter         *auditv1.AuditFilter
	ActorID        *uuid.UUID
	TargetDeviceID *uuid.UUID
	OccurredFrom   pgtype.Timestamptz
	OccurredUntil  pgtype.Timestamptz
	// Kinds the human-actions category omits even when a person caused them.
	HumanExcludedActions []string
	Digest               [sha256.Size]byte
}

// Normalize accepts a schema-validated filter. Absent and empty filters select
// the same rows. UUID spelling is canonicalized for stable cursor bindings.
func Normalize(filter *auditv1.AuditFilter) (Selection, error) {
	// CEL views a Timestamp as an instant and can normalize noncanonical nanos.
	// Preserve the protobuf type's validity before converting or signing it.
	for _, stamp := range [...]*timestamppb.Timestamp{filter.GetOccurredFrom(), filter.GetOccurredUntil()} {
		if stamp != nil {
			if err := stamp.CheckValid(); err != nil {
				return Selection{}, fmt.Errorf("auditfilter: invalid timestamp: %w", err)
			}
		}
	}
	if filter == nil {
		filter = &auditv1.AuditFilter{}
	} else {
		filter = proto.CloneOf(filter)
	}
	selection := Selection{Filter: filter, HumanExcludedActions: auditkind.Strings(auditkind.HumanActionsExcluded()...)}
	if filter.ActorId != nil {
		id, err := uuid.Parse(filter.GetActorId())
		if err != nil {
			return Selection{}, err
		}
		selection.ActorID = &id
		filter.ActorId = new(id.String())
	}
	if filter.TargetDeviceId != nil {
		id, err := uuid.Parse(filter.GetTargetDeviceId())
		if err != nil {
			return Selection{}, err
		}
		selection.TargetDeviceID = &id
		filter.TargetDeviceId = new(id.String())
	}
	selection.OccurredFrom = databaseBoundary(filter.GetOccurredFrom())
	selection.OccurredUntil = databaseBoundary(filter.GetOccurredUntil())
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(filter)
	if err != nil {
		return Selection{}, err
	}
	selection.Digest = sha256.Sum256(encoded)
	return selection, nil
}

// PostgreSQL stores microseconds. Rounding both bounds upward preserves >= from
// and < until exactly even when the protobuf boundary has nanosecond precision.
func databaseBoundary(stamp *timestamppb.Timestamp) pgtype.Timestamptz {
	if stamp == nil {
		return pgtype.Timestamptz{}
	}
	value := stamp.AsTime()
	if remainder := value.Nanosecond() % 1000; remainder != 0 {
		value = value.Add(time.Duration(1000-remainder) * time.Nanosecond)
	}
	return pgtype.Timestamptz{Time: value, Valid: true}
}
