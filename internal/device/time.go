package device

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func timestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

func finiteTime(ts pgtype.Timestamptz) (time.Time, bool) {
	if !ts.Valid || ts.InfinityModifier != pgtype.Finite {
		return time.Time{}, false
	}
	return ts.Time.UTC(), true
}

func protoTime(ts pgtype.Timestamptz) *timestamppb.Timestamp {
	t, ok := finiteTime(ts)
	if !ok {
		return nil
	}
	return timestamppb.New(t)
}
