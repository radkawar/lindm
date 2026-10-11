package reports

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "lindm/gen/lindm/audit/v1"
	integrationsv1 "lindm/gen/lindm/integrations/v1"
)

// Membership/completeness is the server signer's attestation. The search metadata
// for older action rows can come from the action record, not the original payload;
// never pretend to reconstruct that context or chain continuity from selected rows.
func verifyAuditSelection(reader io.Reader, manifest *integrationsv1.ReportManifest) error {
	chain, err := uuid.Parse(manifest.GetChainId())
	if err != nil || chain == uuid.Nil || manifest.GetFormat() != integrationsv1.ReportFormat_REPORT_FORMAT_JSONL || manifest.GetAuditFilter() == nil || len(manifest.GetCapturedHeadHash()) != sha256.Size || manifest.GetAfterSequence() != 0 || len(manifest.GetAfterHash()) != 0 || manifest.GetFinalSequence() != 0 || len(manifest.GetFinalHash()) != 0 {
		return errors.New("reports: invalid audit selection metadata")
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(&auditv1.AuditFilter{}))
	if err != nil {
		return fmt.Errorf("compile audit selection validation: %w", err)
	}
	if err := validator.Validate(manifest.GetAuditFilter()); err != nil {
		return fmt.Errorf("validate audit selection: %w", err)
	}
	for _, stamp := range [...]*timestamppb.Timestamp{manifest.GetAuditFilter().GetOccurredFrom(), manifest.GetAuditFilter().GetOccurredUntil()} {
		if stamp != nil {
			if err := stamp.CheckValid(); err != nil {
				return fmt.Errorf("validate audit selection timestamp: %w", err)
			}
		}
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 32*1024), 64*1024)
	var rows uint64
	var lastTime time.Time
	var lastID uuid.UUID
	for scanner.Scan() {
		record := &integrationsv1.AuditChainRecord{}
		if err := protojson.Unmarshal(scanner.Bytes(), record); err != nil {
			return fmt.Errorf("decode audit selection row: %w", err)
		}
		if record.GetSequence() == 0 || record.GetSequence() > manifest.GetCapturedHeadSequence() || len(record.GetPreviousHash()) != sha256.Size {
			return errors.New("reports: selection row outside captured head")
		}
		hash := sha256.New()
		_, _ = hash.Write([]byte(auditDomain))
		_, _ = hash.Write(chain[:])
		var number [8]byte
		binary.BigEndian.PutUint64(number[:], record.GetSequence())
		_, _ = hash.Write(number[:])
		_, _ = hash.Write(record.GetPreviousHash())
		_, _ = hash.Write(record.GetPayload())
		if !bytes.Equal(hash.Sum(nil), record.GetRowHash()) || (record.GetSequence() == manifest.GetCapturedHeadSequence() && !bytes.Equal(record.GetRowHash(), manifest.GetCapturedHeadHash())) {
			return errors.New("reports: selection row hash mismatch")
		}
		payload := &integrationsv1.AuditEventPayload{}
		if err := protojson.Unmarshal(record.GetPayload(), payload); err != nil {
			return fmt.Errorf("decode audit selection payload: %w", err)
		}
		id, err := uuid.Parse(payload.GetId())
		if err != nil || payload.GetOccurredAt() == nil || payload.GetOccurredAt().CheckValid() != nil {
			return errors.New("reports: invalid selection row identity")
		}
		stamp := payload.GetOccurredAt().AsTime()
		if rows > 0 && (stamp.After(lastTime) || (stamp.Equal(lastTime) && bytes.Compare(id[:], lastID[:]) >= 0)) {
			return errors.New("reports: selection row order or duplicate")
		}
		lastTime, lastID = stamp, id
		rows++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read audit selection: %w", err)
	}
	if rows != manifest.GetRowCount() {
		return errors.New("reports: selection row count mismatch")
	}
	return nil
}
