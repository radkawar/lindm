// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistancefiles"
)

func streamOperation(t *testing.T, direction agentv1.AssistanceFileDirection, data []byte) *fileOperation {
	t.Helper()
	digest := sha256.Sum256(data)
	request := fileDirective(filesInvitation(), time.Now()).GetFileTransfer().GetRequest()
	request.Direction = direction
	if direction == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER {
		request.File = &agentv1.AssistanceFileMetadata{Name: "sample.txt", Size: uint64(len(data)), MimeType: "text/plain", Sha256: digest[:]}
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	t.Cleanup(func() { cancel(errFileCancelled) })
	return &fileOperation{request: request, ctx: ctx, cancel: cancel, release: func() {}, frames: make(chan *agentv1.AssistanceFileFrame, assistancefiles.QueueSize)}
}

func fileChunk(op *fileOperation, offset uint64, data []byte) *agentv1.AssistanceFileFrame {
	return &agentv1.AssistanceFileFrame{RequestId: op.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_Chunk{Chunk: &agentv1.AssistanceFileChunk{Offset: offset, Data: data}}}
}

func fileStart(op *fileOperation) *agentv1.AssistanceFileFrame {
	return &agentv1.AssistanceFileFrame{RequestId: op.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_Start{Start: proto.CloneOf(op.request.GetFile())}}
}

func fileEnd(op *fileOperation) *agentv1.AssistanceFileFrame {
	return &agentv1.AssistanceFileFrame{RequestId: op.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_End{End: &agentv1.AssistanceFileEnd{Size: op.request.GetFile().GetSize(), Sha256: bytes.Clone(op.request.GetFile().GetSha256())}}}
}

func TestFileArrivalSequenceRejectsPreReadyDirectionOffsetDigestAndReplay(t *testing.T) {
	op := streamOperation(t, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER, []byte("abc"))
	if op.acceptFrame(fileChunk(op, 0, []byte("abc"))) {
		t.Fatal("data accepted before Start")
	}
	if !op.acceptFrame(fileStart(op)) {
		t.Fatal("exact server metadata refused")
	}
	if op.acceptFrame(fileChunk(op, 0, []byte("abc"))) {
		t.Fatal("pre-Ready bytes queued for later acceptance")
	}
	if op.acceptFrame(fileStart(op)) {
		t.Fatal("repeated Start accepted")
	}
	op.stage = fileReceiving
	for _, frame := range []*agentv1.AssistanceFileFrame{fileChunk(op, 1, []byte("abc")), fileChunk(op, 0, nil), fileChunk(op, 0, bytes.Repeat([]byte("x"), assistancefiles.ChunkBytes+1)), fileChunk(op, 0, []byte("abcd"))} {
		if op.acceptFrame(frame) {
			t.Fatal("invalid offset/size accepted")
		}
	}
	foreign := fileChunk(op, 0, []byte("abc"))
	foreign.RequestId = "11d2dd4a-e33b-48e3-b7c9-fe6e283350c0"
	if op.acceptFrame(foreign) {
		t.Fatal("foreign request accepted")
	}
	if !op.acceptFrame(fileChunk(op, 0, []byte("abc"))) {
		t.Fatal("ordered payload rejected")
	}
	if op.acceptFrame(fileChunk(op, 0, []byte("abc"))) {
		t.Fatal("duplicate data repeated")
	}
	badEnd := fileEnd(op)
	badEnd.GetEnd().Sha256[0] ^= 1
	if op.acceptFrame(badEnd) {
		t.Fatal("conflicting sender digest accepted")
	}
	if !op.acceptFrame(fileEnd(op)) || op.acceptFrame(fileEnd(op)) {
		t.Fatal("End not single use")
	}

	out := streamOperation(t, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER, nil)
	ready := &agentv1.AssistanceFileFrame{RequestId: out.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_Ready{Ready: &agentv1.AssistanceFileReady{}}}
	if out.acceptFrame(ready) {
		t.Fatal("Ready before sender Start accepted")
	}
	out.stage = fileAwaitReady
	if !out.acceptFrame(ready) || out.acceptFrame(ready) {
		t.Fatal("Ready not single use")
	}
	if out.acceptFrame(fileChunk(out, 0, []byte("remote source"))) {
		t.Fatal("wrong transfer direction accepted")
	}
	receipt := &agentv1.AssistanceFileFrame{RequestId: out.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_Receipt{Receipt: &agentv1.AssistanceFileReceipt{File: op.request.GetFile()}}}
	if out.acceptFrame(receipt) {
		t.Fatal("receipt before End accepted")
	}
	out.stage = fileAwaitReceipt
	out.cancel(errFileCancelled)
	if out.acceptFrame(receipt) {
		t.Fatal("receipt revived cancelled operation")
	}
}

type fileCompletionNotifier struct {
	*fakeNotifier
	fail bool
}

func (n *fileCompletionNotifier) Notify(ctx context.Context, value Notification) (Notice, error) {
	if n.fail && value.Summary == "lindm file received" {
		return nil, errors.New("notification unavailable")
	}
	return n.fakeNotifier.Notify(ctx, value)
}

func TestIncomingStreamVerifiesPublishesAndRequiresCompletionNotification(t *testing.T) {
	for _, mode := range []string{"success", "digest", "type", "notification"} {
		t.Run(mode, func(t *testing.T) {
			data := bytes.Repeat([]byte("x"), assistancefiles.ChunkBytes+1)
			op := streamOperation(t, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER, data)
			if mode == "digest" {
				op.request.File.Sha256[0] ^= 1
			}
			if mode == "type" {
				op.request.File.MimeType = "application/pdf"
				op.request.Policy.AllowedMimeTypes = append(op.request.Policy.AllowedMimeTypes, "application/pdf")
			}
			dir := transferTestDirectory(t)
			target := transferTestIncoming(t, op.ctx, dir, op.request.File.Name, int64(len(data)), nativeTransferPolicy(op.request))
			notifier := &fileCompletionNotifier{fakeNotifier: newFakeNotifier(), fail: mode == "notification"}
			peer := &fakePeer{sentFiles: make(chan []byte, 8)}
			s := &session{deps: &sessionDeps{notifier: notifier, clock: time.Now}, invitation: filesInvitation(), fileOperation: op, fileBusy: true, fileReport: &agentv1.AssistanceFileReport{State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING}}
			op.frames <- fileStart(op)
			op.frames <- fileChunk(op, 0, data[:assistancefiles.ChunkBytes])
			op.frames <- fileChunk(op, assistancefiles.ChunkBytes, data[assistancefiles.ChunkBytes:])
			op.frames <- fileEnd(op)
			verified, err := s.receiveFile(&sessionResources{peer: peer}, op, target)
			if mode == "success" {
				if err != nil || !proto.Equal(verified, op.request.File) {
					t.Fatalf("verified receipt = %v, %v", verified, err)
				}
				if len(peer.sentFiles) != 2 {
					t.Fatal("missing Ready/verified Receipt")
				}
				notice := notifier.next(t, "lindm file received")
				if notice.notification.Body == "" {
					t.Fatal("completion notification missing")
				}
			} else if err == nil || len(peer.sentFiles) != 1 {
				t.Fatal("failed receive falsely acknowledged completion")
			} else if mode == "notification" {
				if !proto.Equal(verified, op.request.File) {
					t.Fatal("published-but-unconfirmed lost independently verified metadata")
				}
				s.updateFile(op, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED, verified.GetSize(), verified, "file_published_unconfirmed")
				if s.fileReport.GetReason() != "file_published_unconfirmed" || !proto.Equal(s.fileReport.GetFile(), verified) {
					t.Fatal("failure report claimed success or lost publication evidence")
				}
			} else if verified != nil {
				t.Fatal("unverified failure echoed authorized metadata")
			}
			published := mode == "success" || mode == "notification"
			if target.Published() != published {
				t.Fatal("publication outcome was not truthful")
			}
			if err := target.Close(); err != nil {
				t.Fatal(err)
			}
			if published {
				actual, err := os.ReadFile(filepath.Join(dir, "sample.txt"))
				if err != nil || sha256.Sum256(actual) != sha256.Sum256(data) {
					t.Fatal("published bytes differ")
				}
			} else {
				transferTestEntries(t, dir, 0)
			}
		})
	}
}

func TestOutgoingStreamRequiresIndependentReceiverReceipt(t *testing.T) {
	for _, goodReceipt := range []bool{true, false} {
		t.Run(map[bool]string{true: "verified", false: "wrong_digest"}[goodReceipt], func(t *testing.T) {
			data := bytes.Repeat([]byte("source "), 6000)
			path := filepath.Join(t.TempDir(), "chosen.txt")
			transferTestWrite(t, path, data)
			op := streamOperation(t, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER, nil)
			source := transferTestOutgoing(t, op.ctx, path, nativeTransferPolicy(op.request))
			peer := &fakePeer{sentFiles: make(chan []byte, 8)}
			s := &session{deps: &sessionDeps{clock: time.Now}, fileOperation: op, fileBusy: true, fileReport: &agentv1.AssistanceFileReport{State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING}}
			done := make(chan error, 1)
			go func() { _, err := s.sendFile(&sessionResources{peer: peer}, op, source); done <- err }()
			readFrame := func() *agentv1.AssistanceFileFrame {
				t.Helper()
				select {
				case raw := <-peer.sentFiles:
					frame := &agentv1.AssistanceFileFrame{}
					if err := proto.Unmarshal(raw, frame); err != nil {
						t.Fatal(err)
					}
					return frame
				case <-time.After(time.Second):
					t.Fatal("stream stalled")
					return nil
				}
			}
			metadata := readFrame().GetStart()
			if metadata == nil || len(metadata.GetSha256()) != 0 {
				t.Fatal("Start claimed receiver verification")
			}
			select {
			case <-done:
				t.Fatal("sender completed without Ready")
			default:
			}
			op.frames <- &agentv1.AssistanceFileFrame{RequestId: op.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_Ready{Ready: &agentv1.AssistanceFileReady{}}}
			digest := sha256.New()
			var count uint64
			for {
				frame := readFrame()
				if chunk := frame.GetChunk(); chunk != nil {
					if chunk.GetOffset() != count || len(chunk.GetData()) > assistancefiles.ChunkBytes {
						t.Fatal("sender violated chunk order/bound")
					}
					if _, err := digest.Write(chunk.GetData()); err != nil {
						t.Fatal(err)
					}
					count += uint64(len(chunk.GetData()))
					continue
				}
				if frame.GetEnd() == nil || frame.GetEnd().GetSize() != count || !bytes.Equal(frame.GetEnd().GetSha256(), digest.Sum(nil)) {
					t.Fatal("sender digest differs from independent receiver")
				}
				break
			}
			select {
			case <-done:
				t.Fatal("End misreported as completion before Receipt")
			default:
			}
			metadata.Sha256 = digest.Sum(nil)
			if !goodReceipt {
				metadata.Sha256[0] ^= 1
			}
			op.frames <- &agentv1.AssistanceFileFrame{RequestId: op.request.GetRequestId(), Body: &agentv1.AssistanceFileFrame_Receipt{Receipt: &agentv1.AssistanceFileReceipt{File: metadata}}}
			if err := <-done; (err == nil) != goodReceipt {
				t.Fatalf("receipt error = %v", err)
			}
		})
	}
}

func TestFileTerminalProjectionSettlesOnlyLiveVerifiedSuccessOnce(t *testing.T) {
	for _, direction := range []agentv1.AssistanceFileDirection{agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER, agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER} {
		for _, cancelled := range []bool{false, true} {
			t.Run(direction.String()+map[bool]string{true: "/cancelled", false: "/live"}[cancelled], func(t *testing.T) {
				op := streamOperation(t, direction, []byte("x"))
				digest := sha256.Sum256([]byte("x"))
				verified := &agentv1.AssistanceFileMetadata{Name: "sample.txt", Size: 1, MimeType: "text/plain", Sha256: digest[:]}
				reservation := uint64(1)
				if direction == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER {
					reservation = op.request.Policy.MaxFileBytes
				}
				s := &session{deps: &sessionDeps{clock: time.Now}, phase: agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE, fileOperation: op, fileBusy: true, fileReserved: reservation}
				if cancelled {
					op.cancel(errFileCancelled)
				}
				s.updateFile(op, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED, 1, verified, "file_verified")
				s.updateFile(op, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED, 1, verified, "file_verified")
				if !cancelled {
					if s.fileReserved != 1 || s.fileReport.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
						t.Fatal("verified success did not settle actual bytes exactly once")
					}
				} else {
					if s.fileReserved != reservation || s.fileReport.GetState() == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
						t.Fatal("cancellation refunded quota or reported success")
					}
					if direction == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER {
						if s.fileReport.GetReason() != "file_published_unconfirmed" || !proto.Equal(s.fileReport.GetFile(), verified) {
							t.Fatal("cancelled publication lost independently verified evidence")
						}
					} else if s.fileReport.GetFile() != nil {
						t.Fatal("cancelled outgoing transfer claimed verified completion")
					}
				}
			})
		}
	}
}
