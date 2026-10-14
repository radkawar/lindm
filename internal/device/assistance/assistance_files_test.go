// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistancefiles"
)

func testAssistanceFilePolicy() *agentv1.AssistanceFilePolicy {
	return &agentv1.AssistanceFilePolicy{MaxFileBytes: 16 << 20, MaxSessionBytes: 64 << 20, AllowedMimeTypes: []string{"text/plain", "application/pdf", "image/png", "image/jpeg"}, AllowedExtensions: []string{".txt", ".log", ".pdf", ".png", ".jpg", ".jpeg"}}
}

func testAssistanceFileRequest(sessionID string, size uint64) *adminv1.StartAssistanceFileTransferRequest {
	return &adminv1.StartAssistanceFileTransferRequest{SessionId: sessionID, Transfer: &agentv1.AssistanceFileRequest{RequestId: uuid.NewString(), Direction: agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER, File: &agentv1.AssistanceFileMetadata{Name: "support.txt", Size: size, MimeType: "text/plain", Sha256: make([]byte, 32)}}}
}

func TestAssistanceFilesPolicyIntersectionAndDefault(t *testing.T) {
	on := allAssistanceCapabilities()
	for _, absent := range []*agentv1.AssistancePolicy{nil, {}, {Files: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON}} {
		if got := intersectAssistancePolicy(on, absent); got.GetFiles() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF || got.GetFileLimits() != nil {
			t.Fatal("unconfigured files became enabled")
		}
	}
	narrow := &agentv1.AssistancePolicy{Files: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, FileLimits: &agentv1.AssistanceFilePolicy{MaxFileBytes: 100, MaxSessionBytes: 500, AllowedMimeTypes: []string{"text/plain"}, AllowedExtensions: []string{".txt"}}}
	got := intersectAssistancePolicy(on, narrow)
	if !proto.Equal(got.GetFileLimits(), narrow.GetFileLimits()) || got.GetFiles() != narrow.GetFiles() {
		t.Fatal("deployment/device limits failed to intersect")
	}
	file := testAssistanceFileRequest(uuid.NewString(), 100).GetTransfer().GetFile()
	if !assistancefiles.MetadataAllowed(got.GetFileLimits(), file, true) {
		t.Fatal("matching allowed metadata denied")
	}
	file.Size++
	if assistancefiles.MetadataAllowed(got.GetFileLimits(), file, true) {
		t.Fatal("over-limit file allowed")
	}
	file.Size, file.Name = 100, "support.pdf"
	if assistancefiles.MetadataAllowed(got.GetFileLimits(), file, true) {
		t.Fatal("MIME alone bypassed extension policy")
	}
	file.Name, file.MimeType = "support.txt", "application/pdf"
	if assistancefiles.MetadataAllowed(got.GetFileLimits(), file, true) {
		t.Fatal("extension alone bypassed MIME policy")
	}
	narrow.FileLimits.AllowedMimeTypes = []string{"image/png"}
	on.FileLimits.AllowedMimeTypes = []string{"text/plain"}
	if intersectAssistancePolicy(on, narrow).GetFiles() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
		t.Fatal("disjoint type policy did not disable files")
	}
}

func TestAssistanceFileSchemaRejectsForgedAuthorityAndPaths(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&adminv1.StartAssistanceFileTransferRequest{}, &agentv1.AssistanceFileReport{}), protovalidate.WithDisableLazy())
	if err != nil {
		t.Fatal(err)
	}
	base := testAssistanceFileRequest(uuid.NewString(), 100)
	for _, tc := range []struct {
		name   string
		change func(*adminv1.StartAssistanceFileTransferRequest)
	}{
		{"deadline", func(r *adminv1.StartAssistanceFileTransferRequest) {
			r.Transfer.Deadline = timestamppb.New(time.Unix(1, 0))
		}},
		{"policy", func(r *adminv1.StartAssistanceFileTransferRequest) { r.Transfer.Policy = testAssistanceFilePolicy() }},
		{"path", func(r *adminv1.StartAssistanceFileTransferRequest) { r.Transfer.File.Name = "../private.txt" }},
		{"windows path", func(r *adminv1.StartAssistanceFileTransferRequest) { r.Transfer.File.Name = `C:\private.txt` }},
		{"digest", func(r *adminv1.StartAssistanceFileTransferRequest) { r.Transfer.File.Sha256 = nil }},
		{"oversized", func(r *adminv1.StartAssistanceFileTransferRequest) { r.Transfer.File.Size = 16<<20 + 1 }},
		{"remote chooser path", func(r *adminv1.StartAssistanceFileTransferRequest) {
			r.Transfer.Direction = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := proto.CloneOf(base)
			tc.change(request)
			if validator.Validate(request) == nil {
				t.Fatal("invalid file authority admitted")
			}
		})
	}
	if err := validator.Validate(base); err != nil {
		t.Fatal(err)
	}
	report := &agentv1.AssistanceFileReport{RequestId: base.Transfer.RequestId, Direction: base.Transfer.Direction, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED, File: base.Transfer.File, BytesTransferred: 100, CompletedAt: timestamppb.New(time.Unix(1, 0))}
	if err := validator.Validate(report); err != nil {
		t.Fatal(err)
	}
	report.BytesTransferred--
	if validator.Validate(report) == nil {
		t.Fatal("success without exact verified size admitted")
	}
	report.BytesTransferred++
	report.State, report.Reason = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED, "file_published_unconfirmed"
	if err := validator.Validate(report); err != nil {
		t.Fatalf("verified uncertain publication rejected: %v", err)
	}
	report.Direction = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER
	if validator.Validate(report) == nil {
		t.Fatal("outgoing report manufactured native publication")
	}
	report.Direction, report.File = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER, nil
	if validator.Validate(report) == nil {
		t.Fatal("unverified publication warning admitted")
	}
	report.State, report.Reason, report.File, report.CompletedAt = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING, "", base.Transfer.File, nil
	if validator.Validate(report) == nil {
		t.Fatal("nonterminal report disclosed unverified metadata")
	}
}

func TestAssistanceFileMetadataDropsUnknownFields(t *testing.T) {
	file := testAssistanceFileRequest(uuid.NewString(), 0).Transfer.File
	file.ProtoReflect().SetUnknown([]byte{0xa2, 0x06, 0x03, 'b', 'a', 'd'})
	if len(assistanceFileMetadata(file).ProtoReflect().GetUnknown()) != 0 {
		t.Fatal("unknown content entered durable metadata")
	}
}
