// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"crypto/sha256"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistancefiles"
)

// The broker authorizes metadata for its SO_PEERCRED-bound helper; it neither
// opens paths nor accepts file content. UID/logind binding is unchanged by files.
func (b *assistanceBroker) applyFileDirective(now time.Time, session *assistanceSession, directive *agentv1.AssistanceFileDirective) {
	if session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		return
	}
	if directive == nil {
		if session.fileDirective != nil && !assistancefiles.Terminal(session.fileReport.GetState()) {
			session.fileDirective.Cancel = true
		}
		return
	}
	request := directive.GetRequest()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "file_directive_invalid")
		return
	}
	digest := sha256.Sum256(encoded)
	if prior, seen := session.fileDigests[request.GetRequestId()]; seen {
		if digest != prior {
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "file_identity_changed")
		} else if session.fileDirective.GetRequest().GetRequestId() == request.GetRequestId() && directive.GetCancel() {
			session.fileDirective.Cancel = true
		}
		return
	}
	// A complete desired-state snapshot may first expose an operation only
	// after cancellation, expiry or server restart. Remember its identity,
	// but never turn a withdrawal into new work or end unrelated assistance.
	if directive.GetCancel() {
		if len(session.fileDigests) >= assistancefiles.MaxOperations {
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "file_operation_limit")
			return
		}
		if session.fileDigests == nil {
			session.fileDigests = make(map[string][32]byte)
		}
		session.fileDigests[request.GetRequestId()] = digest
		if session.fileDirective != nil && !assistancefiles.Terminal(session.fileReport.GetState()) {
			session.fileDirective.Cancel = true
		}
		return
	}
	policy := assistancePolicyIntersection(session.granted.GetPolicy(), assistancePolicyIntersection(session.invitation.GetRequestedCapabilities(), assistancePolicyIntersection(session.invitation.GetEffectiveCapabilities(), b.ceiling)))
	reservation := request.GetFile().GetSize()
	if request.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER {
		reservation = request.GetPolicy().GetMaxFileBytes()
	}
	// Binding presence and a nonroot UID are separate requirements. The
	// production desktop helper refuses euid 0, as does secure file storage.
	if session.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE || session.local == nil || session.local.GetUid() == 0 ||
		!assistancefiles.DirectionAllowed(policy.GetFiles(), request.GetDirection()) || request.GetPolicy() == nil ||
		!proto.Equal(request.GetPolicy(), assistancefiles.Intersect(request.GetPolicy(), policy.GetFileLimits())) ||
		len(session.fileDigests) >= assistancefiles.MaxOperations ||
		(session.fileDirective != nil && !assistancefiles.Terminal(session.fileReport.GetState())) ||
		!now.Before(request.GetDeadline().AsTime()) || request.GetDeadline().AsTime().After(now.Add(5*time.Minute)) || request.GetDeadline().AsTime().After(session.invitation.GetEndsAt().AsTime()) ||
		session.fileReserved > policy.GetFileLimits().GetMaxSessionBytes() || reservation > policy.GetFileLimits().GetMaxSessionBytes()-session.fileReserved ||
		(request.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER && !assistancefiles.MetadataAllowed(request.GetPolicy(), request.GetFile(), true)) {
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "file_not_authorized")
		return
	}
	if session.fileDigests == nil {
		session.fileDigests = make(map[string][32]byte)
	}
	session.fileDigests[request.GetRequestId()] = digest
	session.fileReserved += reservation
	session.fileDirective = proto.CloneOf(directive)
	session.fileReport = nil
	session.fileInputEpoch = session.inputState.GetEpoch()
}

func (b *assistanceBroker) applyFileObservation(now time.Time, session *assistanceSession, observation *agentv1.SessionAssistanceReport) bool {
	input := observation.GetInputState()
	if input == nil || input.GetEpoch() == 0 {
		return false
	}
	prior := session.inputState
	if prior != nil {
		if input.GetEpoch() < prior.GetEpoch() || (input.GetEpoch() == prior.GetEpoch() && input.GetPaused() != prior.GetPaused()) {
			return false
		}
		if input.GetEpoch() > prior.GetEpoch() && session.fileDirective == nil && !elevationTransition(session, prior, input) {
			return false
		}
	} else if input.GetEpoch() != 1 || input.GetPaused() {
		return false
	}
	report := observation.GetFileTransfer()
	if report == nil {
		session.inputState = proto.CloneOf(input)
		return true
	}
	request := session.fileDirective.GetRequest()
	if request == nil || request.GetRequestId() != report.GetRequestId() || request.GetDirection() != report.GetDirection() {
		// Coalesced RPCs may still carry the previous terminal receipt. Its
		// historical identity never starts a new operation or replaces current state.
		_, seen := session.fileDigests[report.GetRequestId()]
		return seen && request.GetRequestId() != report.GetRequestId() && assistancefiles.Terminal(report.GetState())
	}
	publishedUnconfirmed := report.GetState() == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED && report.GetReason() == "file_published_unconfirmed"
	if publishedUnconfirmed && (request.GetDirection() != agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER ||
		!assistancefiles.MetadataAllowed(request.GetPolicy(), report.GetFile(), true) ||
		!proto.Equal(request.GetFile(), report.GetFile()) || report.GetBytesTransferred() != report.GetFile().GetSize()) {
		return false
	}
	old := session.fileReport
	if assistancefiles.Terminal(old.GetState()) {
		if proto.Equal(old, report) {
			return proto.Equal(input, session.inputState)
		}
		if !publishedUnconfirmed || old.GetState() == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
			return false
		}
	}
	if report.GetState() < old.GetState() || report.GetBytesTransferred() < old.GetBytesTransferred() || report.GetBytesTransferred() > request.GetPolicy().GetMaxFileBytes() ||
		(request.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER && report.GetBytesTransferred() > request.GetFile().GetSize()) {
		return false
	}
	terminal := assistancefiles.Terminal(report.GetState())
	if terminal != (report.GetCompletedAt() != nil) || (terminal && report.GetCompletedAt().AsTime().After(now.Add(time.Second))) {
		return false
	}
	if report.GetState() == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_WAITING_CONSENT && !input.GetPaused() && (input.GetEpoch() < session.fileInputEpoch || input.GetEpoch()-session.fileInputEpoch < 2) {
		return false
	}
	if report.GetState() == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING || report.GetState() == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
		if input.GetPaused() || input.GetEpoch() < session.fileInputEpoch || input.GetEpoch()-session.fileInputEpoch < 2 {
			return false
		}
	}
	if report.GetState() == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
		if session.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE || session.fileDirective.GetCancel() || !now.Before(request.GetDeadline().AsTime()) || report.GetCompletedAt().AsTime().After(request.GetDeadline().AsTime()) ||
			!assistancefiles.MetadataAllowed(request.GetPolicy(), report.GetFile(), true) || report.GetFile().GetSize() != report.GetBytesTransferred() ||
			(request.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER && !proto.Equal(request.GetFile(), report.GetFile())) {
			return false
		}
	} else if report.GetFile() != nil && !publishedUnconfirmed {
		return false
	}
	if report.GetState() == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED && request.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER {
		session.fileReserved -= request.GetPolicy().GetMaxFileBytes() - report.GetBytesTransferred()
	}
	session.fileReport = proto.CloneOf(report)
	session.inputState = proto.CloneOf(input)
	return true
}
