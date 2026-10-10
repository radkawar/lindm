package feed

import (
	"errors"
	"testing"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestRedHatSinkCannotMasqueradeAsRejectedVendorRecord(t *testing.T) {
	source := redHatSource("9", "standard")
	stage, err := newRedHatStager(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stage.close(); err != nil {
			t.Error(err)
		}
	})
	vendor := &redHatRejectedRecordError{record: &advisoryv1.RejectedRecord{Id: "CVE-2024-12345", Reason: "simulated vendor-shaped sink failure", Unscoped: true}, cause: errors.New("sink failure")}
	sink := &redHatSinkError{cause: vendor}
	doc := new(advisoryv1.FeedDocument)
	err = acceptRedHatDocument(source, redHatValidator(t), stage, doc, func() error { return sink })
	if !errors.Is(err, sink) || len(doc.RejectedRecords) != 0 {
		t.Fatalf("sink suppressed as vendor rejection: err=%v metadata=%v", err, doc)
	}
}

func TestRedHatRejectedRecordThresholdFailsClosed(t *testing.T) {
	source := redHatSource("9", "standard")
	limit := uint32(0)
	source.MaxRejectedRecords = &limit
	stage, err := newRedHatStager(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stage.close(); err != nil {
			t.Error(err)
		}
	})
	vendor := &redHatRejectedRecordError{record: &advisoryv1.RejectedRecord{Id: "CVE-2024-12345", Reason: "invalid identity", Unscoped: true}, cause: errors.New("invalid identity")}
	doc := new(advisoryv1.FeedDocument)
	if err := acceptRedHatDocument(source, redHatValidator(t), stage, doc, func() error { return vendor }); err == nil || len(doc.RejectedRecords) != 0 {
		t.Fatalf("zero rejection threshold accepted vendor record: err=%v doc=%v", err, doc)
	}
}
