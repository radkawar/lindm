package feed

import (
	"errors"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

type redHatRejectedRecordError struct {
	record *advisoryv1.RejectedRecord
	cause  error
}

func (e *redHatRejectedRecordError) Error() string { return e.cause.Error() }
func (e *redHatRejectedRecordError) Unwrap() error { return e.cause }

// acceptRedHatDocument never keeps a prefix of a rejected vendor document.
// Acquisition, sink, cancellation and storage failures remain source failures.
func acceptRedHatDocument(source *advisoryv1.FeedSource, validator protovalidate.Validator, stager *redHatStager, doc *advisoryv1.FeedDocument, parse func() error) error {
	err := stager.documentClaims(parse)
	if err == nil {
		return nil
	}
	var rejected *redHatRejectedRecordError
	if !errors.As(err, &rejected) {
		return err
	}
	limit := uint32(1000)
	if source.MaxRejectedRecords != nil {
		limit = source.GetMaxRejectedRecords()
	}
	if uint32(len(doc.RejectedRecords)) >= limit {
		return errors.New("feed: rejected record limit exceeded")
	}
	if err := validator.Validate(rejected.record); err != nil {
		return err
	}
	size := proto.Size(rejected.record) + 8
	for _, prior := range doc.RejectedRecords {
		size += proto.Size(prior) + 8
	}
	if size > 48<<10 {
		return errors.New("feed: rejected record metadata byte limit exceeded")
	}
	doc.RejectedRecords = append(doc.RejectedRecords, rejected.record)
	for _, name := range rejected.record.PackageNames {
		for _, sourcePackage := range []bool{false, true} {
			record := &advisoryv1.Advisory{Id: rejected.record.Id, PackageName: name, SourcePackage: sourcePackage, AssessmentUnknown: true, SourceRecordRejected: true, SourceUrl: source.GetUrl(), PlatformRelease: source.GetRelease(), PlatformStream: source.GetPlatformStream()}
			var storage [1]*advisoryv1.Advisory
			pending := advisoryv1.FeedDocument{Advisories: storage[:0]}
			if err := addRecord(&pending, record, "rpm", validator); err != nil {
				return err
			}
			if err := stager.add(record); err != nil {
				return err
			}
		}
	}
	return nil
}
