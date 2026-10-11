package auditfilter

import (
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "lindm/gen/lindm/audit/v1"
)

func TestNormalizeAuditFilterBindsCanonicalUUIDsAndExactTimeEdges(t *testing.T) {
	id := "5b1dcd2c-b257-4da4-a16e-57458454eefe"
	stamp := time.Date(2026, 10, 5, 0, 0, 0, 1, time.UTC)
	lower, err := Normalize(&auditv1.AuditFilter{ActorId: &id, OccurredFrom: timestamppb.New(stamp), OccurredUntil: timestamppb.New(stamp.Add(time.Second))})
	if err != nil {
		t.Fatal(err)
	}
	upper, err := Normalize(&auditv1.AuditFilter{ActorId: new(strings.ToUpper(id)), OccurredFrom: timestamppb.New(stamp), OccurredUntil: timestamppb.New(stamp.Add(time.Second))})
	if err != nil || upper.Digest != lower.Digest {
		t.Fatalf("UUID case changed selection binding: %v", err)
	}
	if !lower.OccurredFrom.Time.Equal(stamp.Add(999*time.Nanosecond)) || !lower.OccurredUntil.Time.Equal(stamp.Add(time.Second+999*time.Nanosecond)) {
		t.Fatal("submicrosecond half-open bounds lost precision")
	}
	if !lower.Filter.GetOccurredFrom().AsTime().Equal(stamp) {
		t.Fatal("signed filter lost original boundary")
	}
	absent, err := Normalize(nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := Normalize(&auditv1.AuditFilter{})
	if err != nil || absent.Digest != empty.Digest {
		t.Fatalf("absent and empty selection differ: %v", err)
	}
}

func TestAuditFilterSchemaRejectsMalformedSelections(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&auditv1.AuditFilter{}))
	if err != nil {
		t.Fatal(err)
	}
	stamp := timestamppb.New(time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC))
	for name, filter := range map[string]*auditv1.AuditFilter{
		"actor":                  {ActorId: new("not-a-uuid")},
		"empty actor":            {ActorId: new("")},
		"target":                 {TargetDeviceId: new("not-a-uuid")},
		"category":               {ActionCategory: auditv1.AuditActionCategory(999)},
		"empty range":            {OccurredFrom: stamp, OccurredUntil: stamp},
		"reversed range":         {OccurredFrom: timestamppb.New(stamp.AsTime().Add(time.Second)), OccurredUntil: stamp},
		"timestamp before range": {OccurredFrom: &timestamppb.Timestamp{Seconds: -62135596801}},
		"timestamp after range":  {OccurredUntil: &timestamppb.Timestamp{Seconds: 253402300800}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validator.Validate(filter); err == nil {
				t.Fatal("malformed filter accepted")
			}
		})
	}
}

func TestNormalizeAuditFilterRejectsNoncanonicalTimestamps(t *testing.T) {
	for name, stamp := range map[string]*timestamppb.Timestamp{
		"negative nanos": {Nanos: -1},
		"excess nanos":   {Nanos: 1000000000},
		"before range":   {Seconds: -62135596801},
		"after range":    {Seconds: 253402300800},
	} {
		t.Run(name, func(t *testing.T) {
			for _, filter := range []*auditv1.AuditFilter{
				{OccurredFrom: stamp},
				{OccurredUntil: stamp},
			} {
				if _, err := Normalize(filter); err == nil {
					t.Fatal("invalid protobuf timestamp accepted")
				}
			}
		})
	}
}
