//go:build linux

package inventory

import (
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestSessionSeatApplicabilitySchemaRequiresNativeContext(t *testing.T) {
	base := &inventoryv1.ActiveSession{
		UserName: observed("lab", nil), SessionClass: observed("user", nil),
		SessionType: observed("tty", nil), Remote: boolean(false, nil),
		Seat: &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE},
	}
	for _, change := range []func(*inventoryv1.ActiveSession){
		func(*inventoryv1.ActiveSession) {},
		func(s *inventoryv1.ActiveSession) {
			s.SessionType.Value = "unspecified"
			s.SessionClass.Value = "manager"
		},
		func(s *inventoryv1.ActiveSession) {
			s.SessionType.Value = "unspecified"
			s.SessionClass.Value = "background"
		},
		func(s *inventoryv1.ActiveSession) { s.SessionType.Value = "x11"; s.Remote.Value = true },
	} {
		session := proto.CloneOf(base)
		change(session)
		if err := protovalidate.Validate(session); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []func(*inventoryv1.ActiveSession){
		func(s *inventoryv1.ActiveSession) { s.SessionType.Value = "x11" },
		func(s *inventoryv1.ActiveSession) { s.SessionType.Value = "wayland" },
		func(s *inventoryv1.ActiveSession) { s.SessionClass = &inventoryv1.ObservedString{Status: unavailable} },
		func(s *inventoryv1.ActiveSession) { s.SessionType = &inventoryv1.ObservedString{Status: unavailable} },
		func(s *inventoryv1.ActiveSession) { s.Remote = &inventoryv1.ObservedBool{Status: unavailable} },
		func(s *inventoryv1.ActiveSession) { s.Seat.Value = "invented-seat" },
	} {
		session := proto.CloneOf(base)
		change(session)
		if err := protovalidate.Validate(session); err == nil {
			t.Fatalf("unsupported non-applicable seat admitted: %v", session)
		}
	}
}

func TestFieldApplicabilityIsNotAPackageFailure(t *testing.T) {
	now := timestamppb.New(time.Unix(1_800_000_000, 0))
	observation := &inventoryv1.PackageObservation{StartedAt: now, FinishedAt: now, Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT}
	request := &devicev1.ReportPackageAttemptRequest{EnrollmentGeneration: "11111111-1111-4111-8111-111111111111", SessionEpoch: 1, Sequence: 1, StartedAt: now, FinishedAt: now, Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT}
	for _, message := range []proto.Message{observation, request} {
		if err := protovalidate.Validate(message); err != nil {
			t.Fatalf("valid package failure rejected: %v", err)
		}
	}
	observation.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE
	request.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE
	for _, message := range []proto.Message{observation, request} {
		if err := protovalidate.Validate(message); err == nil {
			t.Fatal("field applicability accepted as package failure")
		}
	}
}
