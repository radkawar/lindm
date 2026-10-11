package core

import (
	"context"
	"time"

	"lindm/internal/device/devicedb"

	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Timestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

func FiniteTime(ts pgtype.Timestamptz) (time.Time, bool) {
	if !ts.Valid || ts.InfinityModifier != pgtype.Finite {
		return time.Time{}, false
	}
	return ts.Time.UTC(), true
}

func ProtoTime(ts pgtype.Timestamptz) *timestamppb.Timestamp {
	t, ok := FiniteTime(ts)
	if !ok {
		return nil
	}
	return timestamppb.New(t)
}

func DispatchClock(ctx context.Context, q *devicedb.Queries) (time.Time, error) {
	stamp, err := q.ResourceDispatchClock(ctx)
	if err != nil {
		return time.Time{}, err
	}
	now, ok := FiniteTime(stamp)
	if !ok {
		return time.Time{}, ErrInternalState
	}
	return now, nil
}
