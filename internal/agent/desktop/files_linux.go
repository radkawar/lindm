// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"html"
	"io"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistancefiles"
	"lindm/internal/protodata"
)

var (
	errFileCancelled = errors.New("file_cancelled")
	errFileProtocol  = errors.New("file_protocol_invalid")
	errFileDenied    = errors.New("file_declined")
)

type fileOperation struct {
	request  *agentv1.AssistanceFileRequest
	ctx      context.Context
	cancel   context.CancelCauseFunc
	release  context.CancelFunc
	frames   chan *agentv1.AssistanceFileFrame
	streamMu sync.Mutex
	stage    fileStage
	received uint64
}

// applyFile accepts only executor-forwarded server authority. Peer frames cannot
// allocate a transfer, choose a source, approve a file or change the reservation.
func (s *session) applyFile(directive *agentv1.AssistanceFileDirective) {
	if directive != nil && (s.deps == nil || s.deps.validator.Validate(directive) != nil) {
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "file_directive_invalid")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
		return
	}
	if directive == nil {
		if s.fileBusy {
			s.fileOperation.cancel(errFileCancelled)
		}
		return
	}
	request := directive.GetRequest()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return
	}
	digest := sha256.Sum256(encoded)
	if previous, seen := s.fileHistory[request.GetRequestId()]; seen {
		if previous != digest {
			// end cannot be called under mu; cancellation immediately removes all
			// authority and the session loop records the terminal cause.
			s.cancel(errFileProtocol)
		} else if directive.GetCancel() && s.fileBusy && s.fileOperation.request.GetRequestId() == request.GetRequestId() {
			s.fileOperation.cancel(errFileCancelled)
		}
		return
	}
	if directive.GetCancel() {
		if len(s.fileHistory) >= assistancefiles.MaxOperations {
			s.cancel(errFileProtocol)
			return
		}
		// A never-started cancelled operation has no native side effects.
		// Its immutable tombstone prevents a later snapshot from starting it.
		if s.fileHistory == nil {
			s.fileHistory = make(map[string][32]byte)
		}
		s.fileHistory[request.GetRequestId()] = digest
		if s.fileBusy {
			s.fileOperation.cancel(errFileCancelled)
		}
		return
	}
	policy := s.granted.GetPolicy()
	now := s.deps.clock()
	reservation := request.GetFile().GetSize()
	if request.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER {
		reservation = request.GetPolicy().GetMaxFileBytes()
	}
	if s.fileBusy || len(s.fileHistory) >= assistancefiles.MaxOperations ||
		!assistancefiles.DirectionAllowed(policy.GetFiles(), request.GetDirection()) ||
		request.GetPolicy() == nil || !proto.Equal(request.GetPolicy(), assistancefiles.Intersect(request.GetPolicy(), policy.GetFileLimits())) ||
		!now.Before(request.GetDeadline().AsTime()) || request.GetDeadline().AsTime().After(now.Add(5*time.Minute)) || request.GetDeadline().AsTime().After(s.invitation.GetEndsAt().AsTime()) ||
		s.fileReserved > policy.GetFileLimits().GetMaxSessionBytes() || reservation > policy.GetFileLimits().GetMaxSessionBytes()-s.fileReserved ||
		(request.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER && !assistancefiles.MetadataAllowed(request.GetPolicy(), request.GetFile(), true)) {
		s.cancel(errFileProtocol)
		return
	}
	ctx, cancel := context.WithCancelCause(s.life)
	deadline, release := context.WithDeadline(ctx, request.GetDeadline().AsTime())
	op := &fileOperation{request: proto.CloneOf(request), ctx: deadline, cancel: cancel, release: release, frames: make(chan *agentv1.AssistanceFileFrame, assistancefiles.QueueSize)}
	s.fileHistory[request.GetRequestId()] = digest
	s.fileReserved += reservation
	s.fileOperation, s.fileBusy = op, true
	s.fileReport = &agentv1.AssistanceFileReport{RequestId: request.GetRequestId(), Direction: request.GetDirection(), State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_REQUESTED}
	if s.commandCancel != nil {
		s.commandCancel()
	}
	s.files <- op
}

// filePump is the only receiver. Its fixed queue never accumulates modal input;
// cancellation may withdraw native UI, but can never approve it or resume input.
func (s *session) filePump(ctx context.Context, r *sessionResources) {
	defer close(r.filePumpDone)
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-r.peer.Files():
			if !ok {
				s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED, "file_channel_closed")
				return
			}
			frame := &agentv1.AssistanceFileFrame{}
			if len(raw) == 0 || len(raw) > assistancefiles.FrameBytes || proto.Unmarshal(raw, frame) != nil || protodata.ValidateClosed(frame.ProtoReflect()) != nil || s.deps.validator.Validate(frame) != nil {
				s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED, "file_frame_invalid")
				return
			}
			s.mu.Lock()
			op := s.fileOperation
			valid := s.fileBusy && op != nil && frame.GetRequestId() == op.request.GetRequestId()
			if valid && frame.GetCancel() != nil {
				op.cancel(errFileCancelled)
				s.mu.Unlock()
				continue
			}
			valid = valid && s.fileReport.GetState() == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING && op.ctx.Err() == nil
			s.mu.Unlock()
			if valid {
				valid = op.acceptFrame(frame)
			}
			if valid {
				select {
				case op.frames <- frame:
				default:
					valid = false
				}
			}
			if !valid {
				s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED, "file_frame_not_authorized")
				return
			}
		}
	}
}

func (s *session) fileLoop(ctx context.Context, r *sessionResources) {
	defer close(r.fileDone)
	defer func() {
		s.mu.Lock()
		op, busy, count := s.fileOperation, s.fileBusy, s.fileReport.GetBytesTransferred()
		s.mu.Unlock()
		if busy {
			op.cancel(errFileCancelled)
			op.release()
			s.updateFile(op, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED, count, nil, "session_ended")
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case op := <-s.files:
			s.runFile(r, op)
		}
	}
}

func (s *session) updateFile(op *fileOperation, state agentv1.AssistanceFileState, count uint64, file *agentv1.AssistanceFileMetadata, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fileOperation != op || assistancefiles.Terminal(s.fileReport.GetState()) {
		return
	}
	if state == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED && (s.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE || op.ctx.Err() != nil) {
		state, reason = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED, "file_cancelled"
		if op.request.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER {
			state, reason = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED, "file_published_unconfirmed"
		} else {
			file = nil
		}
	}
	if state == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED && op.request.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER {
		s.fileReserved -= op.request.GetPolicy().GetMaxFileBytes() - count
	}
	report := &agentv1.AssistanceFileReport{RequestId: op.request.GetRequestId(), Direction: op.request.GetDirection(), State: state, BytesTransferred: count, File: proto.CloneOf(file), Reason: reason}
	if assistancefiles.Terminal(state) {
		report.CompletedAt = timestamppb.New(s.deps.clock())
		s.fileBusy = false
	}
	s.fileReport = report
}

func (s *session) runFile(r *sessionResources, op *fileOperation) {
	defer op.release()
	defer op.cancel(errFileCancelled)
	incoming, outgoing, err := s.fileConsent(r, op)
	var verified *agentv1.AssistanceFileMetadata
	published := false
	if err == nil {
		s.updateFile(op, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING, 0, nil, "")
		if incoming != nil {
			verified, err = s.receiveFile(r, op, incoming)
			published = incoming.Published()
		} else {
			verified, err = s.sendFile(r, op, outgoing)
		}
	}
	if incoming != nil {
		err = errors.Join(err, incoming.Close())
	}
	if outgoing != nil {
		err = errors.Join(err, outgoing.Close())
	}
	if err == nil {
		s.updateFile(op, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED, verified.GetSize(), verified, "file_verified")
		return
	}
	state, reason := agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED, "file_transfer_failed"
	switch {
	case published:
		reason = "file_published_unconfirmed"
	case errors.Is(err, errElevationPaused):
		state, reason = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED, "local_elevation_pause"
	case errors.Is(err, errFileDenied):
		state, reason = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED, "file_declined"
	case errors.Is(err, ErrPortalCancelled) && op.ctx.Err() == nil:
		state, reason = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED, "file_dialog_dismissed"
	case errors.Is(err, ErrPortalClosed) && op.ctx.Err() == nil:
		state, reason = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED, "file_dialog_closed"
	case op.ctx.Err() != nil:
		state, reason = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED, "file_cancelled"
	case errors.Is(err, errFileProtocol):
		reason = "file_protocol_invalid"
	case errors.Is(err, ErrTransferFileType):
		reason = "file_type_denied"
	case errors.Is(err, ErrTransferFileSize):
		reason = "file_size_denied"
	case errors.Is(err, ErrTransferFileHash):
		reason = "file_digest_mismatch"
	case errors.Is(err, ErrTransferFileChanged):
		reason = "file_source_changed"
	}
	s.mu.Lock()
	count := s.fileReport.GetBytesTransferred()
	s.mu.Unlock()
	if published {
		count = verified.GetSize()
	} else {
		verified = nil
	}
	cancelCtx, cancel := context.WithTimeout(context.Background(), s.deps.callTimeout)
	defer cancel()
	s.logIfErr("withdraw file transfer", sendFileFrame(cancelCtx, r.peer, &agentv1.AssistanceFileFrame{RequestId: op.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_Cancel{Cancel: &agentv1.AssistanceFileCancel{Reason: reason}}}))
	s.updateFile(op, state, count, verified, reason)
}

func nativeTransferPolicy(request *agentv1.AssistanceFileRequest) TransferFilePolicy {
	return TransferFilePolicy{MaxBytes: int64(request.GetPolicy().GetMaxFileBytes()), AllowType: func(contentType, extension string) bool {
		return assistancefiles.Allowed(request.GetPolicy(), contentType, extension) && (request.GetFile() == nil || request.GetFile().GetMimeType() == contentType)
	}}
}

// fileConsent owns modalMu through native completion, not through transport.
// Cancel/expiry/stop joins native withdrawal but does NOT count as local completion:
// those cases end assistance with input still paused (never remote-driven resume).
func (s *session) fileConsent(r *sessionResources, op *fileOperation) (incoming *IncomingTransferFile, outgoing *OutgoingTransferFile, err error) {
	r.modalMu.Lock()
	defer r.modalMu.Unlock()
	if err := op.ctx.Err(); err != nil {
		return nil, nil, err
	}
	if s.elevationPaused() {
		// No file dialog opens over a privileged prompt; the elevation pause
		// stays in force and only the employee resumes it.
		return nil, nil, errElevationPaused
	}
	epoch, err := pauseRemoteInput(op.ctx, r, s.deps.callTimeout)
	s.mu.Lock()
	if epoch != 0 {
		s.inputState = &agentv1.AssistanceInputState{Epoch: epoch, Paused: true}
	}
	expireClipboardResult(s.commandResult, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED, "local_file_dialog")
	s.mu.Unlock()
	if err != nil {
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "input_pause_failed")
		return nil, nil, err
	}
	pause, cancelPause := context.WithTimeout(op.ctx, s.deps.callTimeout)
	err = r.grant.PauseClipboard(pause)
	cancelPause()
	if err != nil {
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "clipboard_pause_failed")
		return nil, nil, err
	}
	s.updateFile(op, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_WAITING_CONSENT, 0, nil, "")
	nativeCompleted := false
	defer func() {
		if op.ctx.Err() != nil || !nativeCompleted {
			s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "file_dialog_withdrawn")
			return
		}
		r.input.mu.Lock()
		defer r.input.mu.Unlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED || op.ctx.Err() != nil {
			return
		}
		if resumeErr := r.grant.ResumeClipboard(); resumeErr != nil {
			err = errors.Join(err, resumeErr)
			s.cancel(resumeErr)
			return
		}
		if !r.input.paused || r.input.epoch == ^uint32(0) {
			err = errors.Join(err, errors.New("input_epoch_exhausted"))
			s.cancel(err)
			return
		}
		r.input.epoch++
		if resumeErr := r.peer.SetInputState(r.input.epoch, false); resumeErr != nil {
			err = errors.Join(err, resumeErr)
			s.cancel(err)
			return
		}
		r.input.paused = false
		s.inputState = &agentv1.AssistanceInputState{Epoch: r.input.epoch}
	}()
	if op.request.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER {
		chosen, chooseErr := s.deps.portal.ChooseFile(op.ctx, "Choose a file to send to "+s.invitation.GetOperatorDisplay())
		// Cancel and close both leave no selection; input resumes and the
		// session continues, with distinct report reasons.
		nativeCompleted = chooseErr == nil || chooseErr == ErrPortalCancelled || chooseErr == ErrPortalClosed
		if chooseErr != nil {
			return nil, nil, chooseErr
		}
		outgoing, err = NewOutgoingTransferFile(op.ctx, chosen, nativeTransferPolicy(op.request))
		return nil, outgoing, err
	}
	approvalErr := s.approveIncoming(r, op)
	nativeCompleted = approvalErr == nil || errors.Is(approvalErr, errFileDenied)
	if approvalErr != nil {
		return nil, nil, approvalErr
	}
	incoming, err = NewIncomingTransferFile(op.ctx, op.request.GetFile().GetName(), int64(op.request.GetFile().GetSize()), nativeTransferPolicy(op.request))
	return incoming, nil, err
}

func (s *session) approveIncoming(r *sessionResources, op *fileOperation) (err error) {
	file := op.request.GetFile()
	body := fmt.Sprintf("%s offers %s (%d bytes, %s). Save this file in your Downloads folder? Remote input and clipboard access are paused.", s.invitation.GetOperatorDisplay(), file.GetName(), file.GetSize(), file.GetMimeType())
	if r.markup {
		body = html.EscapeString(body)
	}
	notice, err := s.postPrompt(op.ctx, r, Notification{Summary: "Receive a file from your support operator", Body: body, Actions: []NotificationAction{{Key: actionAllow, Label: "Save to Downloads"}, {Key: actionDecline, Label: "Decline"}}})
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.deps.callTimeout)
		defer cancel()
		closeErr := notice.Close(ctx)
		err = errors.Join(err, closeErr)
		if closeErr != nil {
			s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "file_notice_withdraw_failed")
		}
	}()
	select {
	case action := <-notice.Result():
		if op.ctx.Err() != nil {
			return op.ctx.Err()
		}
		if action != actionAllow {
			return errFileDenied
		}
		return nil
	case <-op.ctx.Done():
		return op.ctx.Err()
	}
}

func nextFileFrame(op *fileOperation) (*agentv1.AssistanceFileFrame, error) {
	select {
	case <-op.ctx.Done():
		return nil, op.ctx.Err()
	case frame := <-op.frames:
		if err := op.ctx.Err(); err != nil {
			return nil, err
		}
		return frame, nil
	}
}

func sendFileFrame(ctx context.Context, peer Peer, frame *agentv1.AssistanceFileFrame) error {
	data, err := proto.Marshal(frame)
	if err != nil {
		return err
	}
	return peer.SendFile(ctx, data)
}

func (s *session) receiveFile(r *sessionResources, op *fileOperation, target *IncomingTransferFile) (*agentv1.AssistanceFileMetadata, error) {
	file := op.request.GetFile()
	start, err := nextFileFrame(op)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(start.GetStart(), file) {
		return nil, errFileProtocol
	}
	if err := op.sendControl(r.peer, &agentv1.AssistanceFileFrame{RequestId: op.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_Ready{Ready: &agentv1.AssistanceFileReady{}}}, fileReceiving); err != nil {
		return nil, err
	}
	var offset uint64
	for {
		frame, err := nextFileFrame(op)
		if err != nil {
			return nil, err
		}
		if chunk := frame.GetChunk(); chunk != nil {
			if chunk.GetOffset() != offset || len(chunk.GetData()) == 0 || len(chunk.GetData()) > assistancefiles.ChunkBytes || uint64(len(chunk.GetData())) > file.GetSize()-offset {
				return nil, errFileProtocol
			}
			n, err := target.Write(chunk.GetData())
			if err != nil || n != len(chunk.GetData()) {
				return nil, errors.Join(err, io.ErrShortWrite)
			}
			offset += uint64(n)
			s.updateFile(op, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING, offset, nil, "")
			continue
		}
		end := frame.GetEnd()
		if end == nil || end.GetSize() != offset || offset != file.GetSize() || !bytes.Equal(end.GetSha256(), file.GetSha256()) {
			return nil, errFileProtocol
		}
		verified, err := target.Publish([sha256.Size]byte(file.GetSha256()))
		if err != nil && !target.Published() {
			return nil, err
		}
		metadata := &agentv1.AssistanceFileMetadata{Name: file.GetName(), Size: uint64(verified.Size), Sha256: verified.SHA256[:], MimeType: verified.MIME}
		if err != nil {
			return metadata, err
		}
		body := s.invitation.GetOperatorDisplay() + " sent " + file.GetName() + ". The file was saved in your Downloads folder."
		if r.markup {
			body = html.EscapeString(body)
		}
		shown, err := s.indicatorNote(op.ctx, r, "lindm file received", body)
		if err == nil && !shown {
			_, err = s.deps.notifier.Notify(op.ctx, Notification{Summary: "lindm file received", Body: body})
		}
		if err != nil {
			return metadata, err
		}
		if err := sendFileFrame(op.ctx, r.peer, &agentv1.AssistanceFileFrame{RequestId: op.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_Receipt{Receipt: &agentv1.AssistanceFileReceipt{File: metadata}}}); err != nil {
			return metadata, err
		}
		return metadata, nil
	}
}

func (s *session) sendFile(r *sessionResources, op *fileOperation, source *OutgoingTransferFile) (*agentv1.AssistanceFileMetadata, error) {
	name, size, contentType := source.Info()
	metadata := &agentv1.AssistanceFileMetadata{Name: name, Size: uint64(size), MimeType: contentType}
	if err := op.sendControl(r.peer, &agentv1.AssistanceFileFrame{RequestId: op.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_Start{Start: metadata}}, fileAwaitReady); err != nil {
		return nil, err
	}
	ready, err := nextFileFrame(op)
	if err != nil {
		return nil, err
	}
	if ready.GetReady() == nil {
		return nil, errFileProtocol
	}
	var buf [assistancefiles.ChunkBytes]byte
	var offset uint64
	for {
		n, readErr := source.Read(buf[:])
		if n > 0 {
			if err := sendFileFrame(op.ctx, r.peer, &agentv1.AssistanceFileFrame{RequestId: op.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_Chunk{Chunk: &agentv1.AssistanceFileChunk{Offset: offset, Data: buf[:n]}}}); err != nil {
				return nil, err
			}
			offset += uint64(n)
			s.updateFile(op, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING, offset, nil, "")
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
	}
	verified, err := source.Finish()
	if err != nil {
		return nil, err
	}
	metadata.Sha256 = verified.SHA256[:]
	if err := op.sendControl(r.peer, &agentv1.AssistanceFileFrame{RequestId: op.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_End{End: &agentv1.AssistanceFileEnd{Size: metadata.GetSize(), Sha256: metadata.GetSha256()}}}, fileAwaitReceipt); err != nil {
		return nil, err
	}
	receipt, err := nextFileFrame(op)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(receipt.GetReceipt().GetFile(), metadata) {
		return nil, errFileProtocol
	}
	return metadata, nil
}

type fileStage uint8

const (
	fileNew fileStage = iota
	fileStartReceived
	fileReceiving
	fileEndReceived
	fileAwaitReady
	fileSending
	fileAwaitReceipt
	fileReceiptReceived
)

// acceptFrame checks arrival order, not just dequeue order: a frame queued
// before Ready/End was issued cannot become valid by waiting in the receiver.
func (op *fileOperation) acceptFrame(frame *agentv1.AssistanceFileFrame) bool {
	op.streamMu.Lock()
	defer op.streamMu.Unlock()
	if op.ctx.Err() != nil || frame.GetRequestId() != op.request.GetRequestId() {
		return false
	}
	if op.request.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER {
		switch op.stage {
		case fileNew:
			if frame.GetStart() == nil || !proto.Equal(frame.GetStart(), op.request.GetFile()) {
				return false
			}
			op.stage = fileStartReceived
			return true
		case fileReceiving:
			if chunk := frame.GetChunk(); chunk != nil {
				if chunk.GetOffset() != op.received || len(chunk.GetData()) == 0 || len(chunk.GetData()) > assistancefiles.ChunkBytes || uint64(len(chunk.GetData())) > op.request.GetFile().GetSize()-op.received {
					return false
				}
				op.received += uint64(len(chunk.GetData()))
				return true
			}
			if end := frame.GetEnd(); end != nil && end.GetSize() == op.received && end.GetSize() == op.request.GetFile().GetSize() && bytes.Equal(end.GetSha256(), op.request.GetFile().GetSha256()) {
				op.stage = fileEndReceived
				return true
			}
		}
		return false
	}
	switch op.stage {
	case fileAwaitReady:
		if frame.GetReady() != nil {
			op.stage = fileSending
			return true
		}
	case fileAwaitReceipt:
		if frame.GetReceipt() != nil {
			op.stage = fileReceiptReceived
			return true
		}
	}
	return false
}

func (op *fileOperation) sendControl(peer Peer, frame *agentv1.AssistanceFileFrame, next fileStage) error {
	op.streamMu.Lock()
	defer op.streamMu.Unlock()
	if err := sendFileFrame(op.ctx, peer, frame); err != nil {
		return err
	}
	op.stage = next
	return nil
}
