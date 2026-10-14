// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func brokerFileLimits() *agentv1.AssistanceFilePolicy {
	return &agentv1.AssistanceFilePolicy{MaxFileBytes: 64, MaxSessionBytes: 128, AllowedMimeTypes: []string{"text/plain"}, AllowedExtensions: []string{".txt"}}
}

func brokerFileRequest(f *assistanceFixture, direction agentv1.AssistanceFileDirection) *agentv1.AssistanceFileDirective {
	request := &agentv1.AssistanceFileRequest{RequestId: uuid.NewString(), Direction: direction, Deadline: timestamppb.New(f.clock().Add(time.Minute)), Policy: brokerFileLimits()}
	if direction == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER {
		digest := sha256.Sum256([]byte("x"))
		request.File = &agentv1.AssistanceFileMetadata{Name: "note.txt", Size: 1, MimeType: "text/plain", Sha256: digest[:]}
	}
	return &agentv1.AssistanceFileDirective{Request: request}
}

func TestAssistanceFilesBindUIDProjectEpochAndDoNotReplay(t *testing.T) {
	f, directive, observation := activeCapabilitiesFixture(t)
	id := directive.Invitation.SessionId
	directive.FileTransfer = brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER)
	request := directive.FileTransfer.Request
	f.network(directive)
	if got := f.mustHelper(1000, observation)[id].GetFileTransfer(); !proto.Equal(got, directive.FileTransfer) {
		t.Fatal("exact metadata authority lost")
	}
	if got := f.mustHelper(1001); len(got) != 0 {
		t.Fatal("foreign UID received source authority")
	}
	observation.InputState = &agentv1.AssistanceInputState{Epoch: 2, Paused: true}
	observation.FileTransfer = &agentv1.AssistanceFileReport{RequestId: request.RequestId, Direction: request.Direction, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_WAITING_CONSENT}
	f.mustHelper(1000, observation)
	if state := f.network(directive)[id].GetInputState(); !state.GetPaused() || state.GetEpoch() != 2 {
		t.Fatal("input pause lost in projection")
	}
	observation.InputState = &agentv1.AssistanceInputState{Epoch: 3}
	observation.FileTransfer.State = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED
	observation.FileTransfer.File = proto.CloneOf(request.File)
	observation.FileTransfer.BytesTransferred = request.File.Size
	observation.FileTransfer.CompletedAt = timestamppb.New(f.clock())
	f.mustHelper(1001, observation)
	if state := f.network(directive)[id].GetFileTransfer(); state.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_WAITING_CONSENT {
		t.Fatal("foreign UID manufactured receiver success")
	}
	f.mustHelper(1000, observation)
	if state := f.network(directive)[id]; !proto.Equal(state.GetFileTransfer(), observation.FileTransfer) || state.GetInputState().GetEpoch() != 3 || state.GetDisplayGeneration() != 1 {
		t.Fatal("verified receipt or independent input epoch lost")
	}
	reserved := f.broker.sessions[id].fileReserved
	for range 3 {
		f.network(directive)
		f.mustHelper(1000, observation)
	}
	if f.broker.sessions[id].fileReserved != reserved {
		t.Fatal("repeated operation consumed quota or repeated authority")
	}
	changed := proto.CloneOf(directive)
	changed.FileTransfer.Request.File.Name = "other.txt"
	wantEnded(t, f.network(changed)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
}

func TestAssistanceFileReportRejectsUnverifiedDirectionDigestOrderAndEpoch(t *testing.T) {
	for _, name := range []string{"direction", "digest", "size", "type", "epoch_missing", "epoch_old", "paused", "receipt_before_local_completion", "unknown_id"} {
		t.Run(name, func(t *testing.T) {
			f, directive, observation := activeCapabilitiesFixture(t)
			id := directive.Invitation.SessionId
			directive.FileTransfer = brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER)
			request := directive.FileTransfer.Request
			f.network(directive)
			observation.InputState = &agentv1.AssistanceInputState{Epoch: 3}
			observation.FileTransfer = &agentv1.AssistanceFileReport{RequestId: request.RequestId, Direction: request.Direction, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED, File: proto.CloneOf(request.File), BytesTransferred: request.File.Size, CompletedAt: timestamppb.New(f.clock())}
			switch name {
			case "direction":
				observation.FileTransfer.Direction = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER
			case "digest":
				observation.FileTransfer.File.Sha256[0] ^= 1
			case "size":
				observation.FileTransfer.File.Size++
				observation.FileTransfer.BytesTransferred++
			case "type":
				observation.FileTransfer.File.MimeType = "application/pdf"
			case "epoch_missing":
				observation.InputState = nil
			case "epoch_old":
				observation.InputState.Epoch = 1
			case "paused":
				observation.InputState.Paused = true
			case "receipt_before_local_completion":
				observation.InputState.Epoch = 2
			case "unknown_id":
				observation.FileTransfer.RequestId = uuid.NewString()
			}
			f.mustHelper(1000, observation)
			wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
		})
	}
}

func TestAssistanceFilesEnforceOwnIntersectionAndConservativeReservations(t *testing.T) {
	for _, name := range []string{"size", "policy", "deadline", "type"} {
		t.Run(name, func(t *testing.T) {
			f, directive, _ := activeCapabilitiesFixture(t)
			directive.FileTransfer = brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER)
			r := directive.FileTransfer.Request
			switch name {
			case "size":
				r.File.Size = 65
			case "policy":
				r.Policy.MaxFileBytes = 65
			case "deadline":
				r.Deadline = timestamppb.New(f.clock().Add(6 * time.Minute))
			case "type":
				r.File.MimeType = "application/pdf"
			}
			wantEnded(t, f.network(directive)[directive.Invitation.SessionId], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
		})
	}
	f, directive, observation := activeCapabilitiesFixture(t)
	id := directive.Invitation.SessionId
	for i := range 2 {
		directive.FileTransfer = brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER)
		if i == 1 {
			directive.FileTransfer.Request.Policy.MaxSessionBytes = 64
		}
		if state := f.network(directive)[id]; state.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
			t.Fatal("server remaining quota subtracted twice")
		}
		observation.InputState = &agentv1.AssistanceInputState{Epoch: uint32(3 + i*2)}
		observation.FileTransfer = &agentv1.AssistanceFileReport{RequestId: directive.FileTransfer.Request.RequestId, Direction: directive.FileTransfer.Request.Direction, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED, CompletedAt: timestamppb.New(f.clock())}
		f.mustHelper(1000, observation)
	}
	directive.FileTransfer = brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER)
	wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
}

func TestAssistanceFileCountAndAuthorityExpiryAreBounded(t *testing.T) {
	f, directive, observation := activeCapabilitiesFixture(t)
	id := directive.Invitation.SessionId
	for range 32 {
		directive.FileTransfer = brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER)
		if state := f.network(directive)[id]; state.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
			t.Fatal("bounded operation unexpectedly refused")
		}
		observation.FileTransfer = &agentv1.AssistanceFileReport{RequestId: directive.FileTransfer.Request.RequestId, Direction: directive.FileTransfer.Request.Direction, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED, CompletedAt: timestamppb.New(f.clock())}
		f.mustHelper(1000, observation)
	}
	directive.FileTransfer = brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER)
	wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
	f, directive, observation = activeCapabilitiesFixture(t)
	id = directive.Invitation.SessionId
	directive.FileTransfer = brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER)
	f.network(directive)
	f.advance(assistanceReauthorization)
	f.broker.mu.Lock()
	f.broker.expire(f.clock())
	f.broker.mu.Unlock()
	if !f.broker.sessions[id].fileDirective.GetCancel() {
		t.Fatal("authority expiry retained live file operation")
	}
	if stop := f.mustHelper(1000, observation)[id]; !stop.GetTerminate() {
		t.Fatal("expired authority did not withdraw native session")
	}
}

func TestAssistanceRetainsVerifiedUnconfirmedPublicationAfterSessionEnd(t *testing.T) {
	for _, matching := range []bool{true, false} {
		t.Run(map[bool]string{true: "verified", false: "wrong_digest"}[matching], func(t *testing.T) {
			f, directive, observation := activeCapabilitiesFixture(t)
			id := directive.Invitation.SessionId
			directive.FileTransfer = brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER)
			request := directive.FileTransfer.Request
			f.network(directive)
			directive.Terminate = true
			directive.TerminateCause = agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED
			f.network(directive)
			observation.Phase = agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED
			observation.EndCause = directive.TerminateCause
			observation.InputState = &agentv1.AssistanceInputState{Epoch: 3}
			observation.FileTransfer = &agentv1.AssistanceFileReport{RequestId: request.RequestId, Direction: request.Direction,
				State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED, Reason: "file_published_unconfirmed",
				BytesTransferred: request.File.Size, File: proto.CloneOf(request.File), CompletedAt: timestamppb.New(f.clock())}
			if !matching {
				observation.FileTransfer.File.Sha256[0] ^= 1
			}
			f.mustHelper(1000, observation)
			state := f.network(directive)[id]
			wantEnded(t, state, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED)
			if matching {
				if !proto.Equal(state.GetFileTransfer(), observation.FileTransfer) {
					t.Fatal("session end erased verified publication failure")
				}
			} else if state.GetFileTransfer().GetFile() != nil {
				t.Fatal("session end accepted forged publication evidence")
			}
		})
	}
}

func TestAssistanceVerifiedSuccessChargesActualBytesExactlyOnce(t *testing.T) {
	f, directive, observation := activeCapabilitiesFixture(t)
	id := directive.Invitation.SessionId
	directive.FileTransfer = brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER)
	request := directive.FileTransfer.Request
	f.network(directive)
	metadata := brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER).Request.File
	observation.InputState = &agentv1.AssistanceInputState{Epoch: 3}
	observation.FileTransfer = &agentv1.AssistanceFileReport{RequestId: request.RequestId, Direction: request.Direction,
		State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED, BytesTransferred: metadata.Size,
		File: metadata, CompletedAt: timestamppb.New(f.clock())}
	f.mustHelper(1000, observation)
	f.mustHelper(1000, observation)
	f.broker.mu.Lock()
	charged := f.broker.sessions[id].fileReserved
	f.broker.mu.Unlock()
	if charged != metadata.Size {
		t.Fatalf("verified charge = %d, want %d exactly once", charged, metadata.Size)
	}
	directive.FileTransfer = brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER)
	directive.FileTransfer.Request.Policy.MaxSessionBytes -= metadata.Size
	if report := f.network(directive)[id]; report.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
		t.Fatal("successful transfer retained unused reservation")
	}
}

func TestAssistanceUnseenFileCancellationDoesNotEndOrStartSessionWork(t *testing.T) {
	f, directive, observation := activeCapabilitiesFixture(t)
	id := directive.Invitation.SessionId
	directive.FileTransfer = brokerFileRequest(f, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER)
	directive.FileTransfer.Cancel = true
	if got := f.network(directive)[id]; got.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
		t.Fatalf("never-started cancellation ended assistance: %v", got)
	}
	session := f.broker.sessions[id]
	if session.fileDirective != nil || session.fileReserved != 0 || len(session.fileDigests) != 1 {
		t.Fatal("withdrawal allocated transfer authority or lost its replay tombstone")
	}
	if got := f.mustHelper(1000, observation)[id]; got.GetFileTransfer() != nil {
		t.Fatal("never-started cancellation reached the helper as new authority")
	}
	directive.FileTransfer.Cancel = false
	f.network(directive)
	if session.fileDirective != nil || session.fileReserved != 0 {
		t.Fatal("a later stale active snapshot resurrected the cancelled operation")
	}
	directive.FileTransfer.Request.File.Name = "changed.txt"
	wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
}
