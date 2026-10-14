// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

// Browser observations describe physical protocol probes, never their native
// outcome. GTK callbacks, compositor pixels and no-follow filesystem reads are
// independent witnesses. The parent binds this entire proof as an artifact.
type assistanceFileInputProbe struct {
	Channel        string   `json:"channel"`
	Ordered        bool     `json:"ordered"`
	Frames         []string `json:"frames"`
	BufferedAmount uint64   `json:"buffered_amount"`
}

type assistanceFileModalRefusal struct {
	RequestID  string                   `json:"request_id"`
	Kind       string                   `json:"kind"`
	Actor      *assistanceActor         `json:"actor"`
	Code       string                   `json:"code"`
	Reason     string                   `json:"reason"`
	HTTPStatus int                      `json:"http_status"`
	Audit      *assistanceAuditEvidence `json:"audit"`
}

type assistanceFilePartial struct {
	RequestID          string                        `json:"request_id"`
	Channel            string                        `json:"channel"`
	Ordered            bool                          `json:"ordered"`
	BytesSent          uint64                        `json:"bytes_sent"`
	ReadyFrame         []byte                        `json:"ready_frame"`
	BufferedAmount     uint64                        `json:"buffered_amount"`
	Stage              *assistanceFileStage          `json:"stage"`
	SourcePrefixSHA256 string                        `json:"source_prefix_sha256"`
	Report             *agentv1.AssistanceFileReport `json:"report"`
}

type assistanceFileStage struct {
	Name   string `json:"name"`
	UID    uint32 `json:"uid"`
	Mode   uint32 `json:"mode"`
	Bytes  uint64 `json:"bytes"`
	SHA256 string `json:"sha256"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type assistanceFileIsolationProof struct {
	SessionID         string                        `json:"session_id"`
	Attempt           *assistanceFileAttempt        `json:"attempt"`
	Initial           *agentv1.AssistanceInputState `json:"initial_input"`
	Display           string                        `json:"display"`
	Generation        uint32                        `json:"generation"`
	Capture           assistanceFileInputProbe      `json:"capture"`
	Hold              assistanceFileInputProbe      `json:"hold"`
	Modal             assistanceFileInputProbe      `json:"modal"`
	Replay            assistanceFileInputProbe      `json:"replay"`
	ModalBefore       *agentv1.AssistanceFileReport `json:"modal_before"`
	ModalAfter        *agentv1.AssistanceFileReport `json:"modal_after"`
	Baseline          *assistanceFixtureState       `json:"baseline"`
	Held              *assistanceFixtureState       `json:"held"`
	Paused            *assistanceFixtureState       `json:"paused"`
	Probed            *assistanceFixtureState       `json:"probed"`
	Resumed           *assistanceFixtureState       `json:"resumed"`
	Final             *assistanceFixtureState       `json:"final"`
	BeforeScreenshot  string                        `json:"before_screenshot"`
	AfterScreenshot   string                        `json:"after_screenshot"`
	ModalScreenshot   string                        `json:"modal_screenshot"`
	ModalOCR          string                        `json:"modal_ocr"`
	ApprovalX         float64                       `json:"approval_x"`
	ApprovalY         float64                       `json:"approval_y"`
	ProbeNonce        string                        `json:"probe_nonce"`
	Refusals          []assistanceFileModalRefusal  `json:"refusals"`
	Partial           []assistanceFilePartial       `json:"partial"`
	CancelFrame       []byte                        `json:"cancel_frame"`
	RequestAudit      *assistanceAuditEvidence      `json:"request_audit"`
	Reservation       *assistanceFileAttempt        `json:"reservation_attempt"`
	ReservationAudit  *assistanceAuditEvidence      `json:"reservation_request_audit"`
	RetainedInput     *agentv1.AssistanceInputState `json:"retained_input"`
	RetainedSessionID string                        `json:"retained_session_id"`
	RetainedPhase     adminv1.AssistanceState       `json:"retained_phase"`
}

func isolationFrames(display string, generation, epoch uint32, code string, held bool) []string {
	frame := func(down bool) string {
		return fmt.Sprintf(`{"t":"key","code":%s,"down":%t,"display":%s,"generation":%d,"epoch":%d}`, strconv.Quote(code), down, strconv.Quote(display), generation, epoch)
	}
	frames := []string{frame(true)}
	if !held {
		frames = append(frames, frame(false))
	}
	return frames
}

func isolationModalFrames(p *assistanceFileIsolationProof) []string {
	var frames []string
	for _, epoch := range []uint32{p.Attempt.Paused.GetEpoch(), p.Attempt.Paused.GetEpoch() + 1} {
		for _, point := range [][2]float64{{p.ApprovalX, p.ApprovalY}, {0.5, 0.6}} {
			frames = append(frames, fmt.Sprintf(`{"t":"move","x":%g,"y":%g,"display":%s,"generation":%d,"epoch":%d}`, point[0], point[1], strconv.Quote(p.Display), p.Generation, epoch))
			for _, down := range []bool{true, false} {
				frames = append(frames, fmt.Sprintf(`{"t":"button","b":"left","down":%t,"display":%s,"generation":%d,"epoch":%d}`, down, strconv.Quote(p.Display), p.Generation, epoch))
			}
		}
		frames = append(frames, isolationFrames(p.Display, p.Generation, epoch, "Enter", false)...)
		frames = append(frames, isolationFrames(p.Display, p.Generation, epoch, "KeyX", false)...)
	}
	return frames
}

func (r *assistanceRun) isolationInput(ctx context.Context, frames []string, result *assistanceFileInputProbe) error {
	return r.browser.call(ctx, "fileIsolationInput", map[string]any{"frames": frames}, result, 30*time.Second)
}

func (r *assistanceRun) isolationReport(ctx context.Context, method, request string) (*agentv1.AssistanceFileReport, error) {
	var raw json.RawMessage
	if err := r.browser.call(ctx, method, map[string]any{"requestId": request}, &raw, 40*time.Second); err != nil {
		return nil, err
	}
	report := new(agentv1.AssistanceFileReport)
	if err := protojson.Unmarshal(raw, report); err != nil {
		return nil, err
	}
	if !vmValidID(report.GetRequestId()) || (request != "" && report.GetRequestId() != request) {
		return nil, errors.New("isolation report identity mismatch")
	}
	return report, nil
}

func (r *assistanceRun) isolationPaste(ctx context.Context) (*assistanceFixtureState, error) {
	before, err := r.waitFixture(ctx, "local paste release baseline", func(*assistanceFixtureState) bool { return true })
	if err != nil {
		return nil, err
	}
	if _, err := r.localClipboardPaste(ctx); err != nil {
		return nil, err
	}
	return r.waitFixture(ctx, "completed local Ctrl+V callbacks", func(state *assistanceFixtureState) bool {
		return len(state.Releases) >= len(before.Releases)+2 && state.PasteSerial > before.PasteSerial
	})
}

func (r *assistanceRun) isolationScreenshot(ctx context.Context, scenario *assistanceScenarioEvidence, label string) (string, error) {
	image, err := r.vm.guest.screendump(ctx)
	if err != nil {
		return "", err
	}
	path, err := r.screen.save(scenario.Name+"-"+label, image)
	if err == nil {
		scenario.Screenshots = append(scenario.Screenshots, path)
	}
	return path, err
}

func (r *assistanceRun) fileInterruptedScenario(ctx context.Context, scenario *assistanceScenarioEvidence) (_ *assistanceFileIsolationProof, err error) {
	p := &assistanceFileIsolationProof{SessionID: scenario.SessionID, Attempt: new(assistanceFileAttempt)}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		err = errors.Join(err, r.browser.call(cleanup, "fileIsolationCleanup", nil, nil, 10*time.Second))
	}()
	if err := r.startFixture(ctx, 1); err != nil {
		return nil, err
	}
	restoreReference, err := r.useFixtureReference(ctx)
	if err != nil {
		return nil, err
	}
	defer restoreReference()
	if _, err := r.pointerWitness(ctx, 0, 0.5, 0.6); err != nil {
		return nil, err
	}
	if err := r.browser.call(ctx, "keys", map[string]any{"key": "Control+c", "mode": "Physical keys"}, nil, 30*time.Second); err != nil {
		return nil, err
	}
	if _, err := r.waitFixture(ctx, "native copy key releases", func(s *assistanceFixtureState) bool {
		return slices.Contains(s.Releases, "c") && slices.Contains(s.Releases, "Control_L")
	}); err != nil {
		return nil, err
	}
	if _, err := r.isolationPaste(ctx); err != nil {
		return nil, err
	}
	fixture, err := r.fileFixture(16<<20, false)
	if err != nil {
		return nil, err
	}
	p.Attempt.Source, err = r.bindFileFixture(fixture)
	if err != nil {
		return nil, err
	}
	p.Attempt.Before, err = r.observeGuestFile(ctx, fixture.Name, true)
	if err != nil {
		return nil, err
	}
	if p.Attempt.Before.Exists || len(p.Attempt.Before.Staging) != 0 {
		return nil, errors.New("isolation destination or staging already exists")
	}
	var prepared assistanceFileFixture
	if err := r.browser.call(ctx, "fileIsolationPrepare", map[string]any{"file": fixture.Path}, &prepared, 45*time.Second); err != nil {
		return nil, err
	}
	if prepared.Name != fixture.Name || prepared.Bytes != fixture.Bytes || prepared.SHA256 != fixture.SHA256 {
		return nil, errors.New("real browser File differs from independent host source")
	}
	session, err := r.waitSession(ctx, scenario, 20*time.Second, "initial live input epoch", func(s *adminv1.AssistanceSession) bool {
		return s.GetInputState().GetEpoch() != 0 && !s.GetInputState().GetPaused() && !ended(s)
	})
	if err != nil {
		return nil, err
	}
	p.Initial, p.Display, p.Generation = session.GetInputState(), session.GetSelectedDisplayId(), session.GetDisplayGeneration()
	if err := r.isolationInput(ctx, isolationFrames(p.Display, p.Generation, p.Initial.GetEpoch(), "KeyY", false), &p.Capture); err != nil {
		return nil, err
	}
	p.Baseline, err = r.waitFixture(ctx, "captured premodal KeyY", func(s *assistanceFixtureState) bool {
		return len(s.Keys) > 0 && s.Keys[len(s.Keys)-1].Symbol == "y" && len(s.Releases) > 0 && s.Releases[len(s.Releases)-1] == "y"
	})
	if err != nil {
		return nil, err
	}
	if err := r.isolationInput(ctx, isolationFrames(p.Display, p.Generation, p.Initial.GetEpoch(), "ShiftLeft", true), &p.Hold); err != nil {
		return nil, err
	}
	p.Held, err = r.waitFixture(ctx, "genuine held remote Shift", func(s *assistanceFixtureState) bool { return len(s.Keys) == len(p.Baseline.Keys)+1 })
	if err != nil {
		return nil, err
	}
	p.BeforeScreenshot, err = r.isolationScreenshot(ctx, scenario, "held-key")
	if err != nil {
		return nil, err
	}
	requested, err := r.isolationReport(ctx, "fileIsolationStart", "")
	if err != nil {
		return nil, err
	}
	request := requested.GetRequestId()
	// Poll authoritative responses for this exact operation, never a timer or a
	// browser progress label. Its sender remains the unmodified production UI.
	paused, err := r.waitSession(ctx, scenario, 30*time.Second, "native file modal epoch", func(s *adminv1.AssistanceSession) bool {
		return s.GetInputState().GetPaused() && s.GetInputState().GetEpoch() > p.Initial.GetEpoch()
	})
	if err != nil {
		return nil, err
	}
	p.Attempt.Paused = paused.GetInputState()
	waiting, err := r.isolationReport(ctx, "fileIsolationState", request)
	if err != nil {
		return nil, err
	}
	if waiting.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_WAITING_CONSENT {
		return nil, errors.New("incoming modal not waiting for genuine local consent")
	}
	p.ModalBefore = waiting
	p.Paused, err = r.waitFixture(ctx, "modal releasing held remote Shift", func(s *assistanceFixtureState) bool { return len(s.Releases) > len(p.Held.Releases) })
	if err != nil {
		return nil, err
	}
	image, banner, err := r.screen.waitBanner(ctx, 30*time.Second)
	if err != nil {
		return nil, err
	}
	p.ModalScreenshot, err = r.screen.save(scenario.Name+"-isolated-approval", image)
	if err != nil {
		return nil, err
	}
	scenario.Screenshots = append(scenario.Screenshots, p.ModalScreenshot)
	text, err := r.bannerOCR(ctx, p.ModalScreenshot, image, banner)
	if err != nil {
		return nil, err
	}
	p.ModalOCR = string(text)
	if !fileNoticeVisible(p.ModalOCR, scenario.OperatorDisplay, fixture.Name, false) {
		return nil, errors.New("real native incoming approval not visible")
	}
	// Save, Decline, then the indicator's Stop.
	point := notificationActionPoint(banner, 3, 0)
	p.ApprovalX, p.ApprovalY = float64(point.X-image.Bounds().Min.X)/float64(image.Bounds().Dx()), float64(point.Y-image.Bounds().Min.Y)/float64(image.Bounds().Dy())
	if err := r.isolationInput(ctx, isolationModalFrames(p), &p.Modal); err != nil {
		return nil, err
	}
	p.ProbeNonce, err = assistanceNonce()
	if err != nil {
		return nil, err
	}
	for _, kind := range []string{"clipboard_write", "clipboard_read", "special_keys"} {
		var refusal assistanceFileModalRefusal
		if err := r.browser.call(ctx, "fileModalRefuse", map[string]any{"kind": kind, "text": p.ProbeNonce}, &refusal, 40*time.Second); err != nil {
			return nil, err
		}
		action := "assistance.clipboard"
		if kind == "special_keys" {
			action = "assistance.special_keys"
		}
		refusal.Audit, err = r.authorizationAudit(ctx, scenario.SessionID, scenario.OperatorID, action, refusal.RequestID)
		if err != nil {
			return nil, err
		}
		p.Refusals = append(p.Refusals, refusal)
	}
	p.Probed, err = r.isolationPaste(ctx)
	if err != nil {
		return nil, err
	}
	waiting, err = r.isolationReport(ctx, "fileIsolationState", request)
	if err != nil {
		return nil, err
	}
	if waiting.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_WAITING_CONSENT || waiting.GetBytesTransferred() != 0 {
		return nil, errors.New("remote modal probe approved or streamed a file")
	}
	p.ModalAfter = waiting
	p.Attempt.ConsentScreenshot, p.Attempt.ConsentOCR, err = r.fileIncomingDecision(ctx, scenario, request, fixture.Name, true)
	if err != nil {
		return nil, err
	}
	p.Attempt.Resumed, err = r.fileResumed(ctx, scenario, p.Attempt.Paused)
	if err != nil {
		return nil, err
	}
	// Refocus the fixture using the independent local seat; the remote probe's
	// pointer must not be mistaken for this intentional local click. The
	// fullscreen witness has no hover feedback and GNOME drew no pointer over
	// it, so the native witness, not a hover, confirms the click
	// (layers-fedora44-files-18/-19).
	if _, err := r.localFixtureClick(ctx, scenario, [2]float64{0.5, 0.5}); err != nil {
		return nil, err
	}
	p.Resumed, err = r.waitFixture(ctx, "local fixture refocus", func(s *assistanceFixtureState) bool { return len(s.Clicks) > len(p.Probed.Clicks) })
	if err != nil {
		return nil, err
	}
	replay := append(slices.Clone(p.Capture.Frames), isolationFrames(p.Display, p.Generation, p.Attempt.Resumed.GetEpoch(), "KeyZ", false)...)
	if err := r.isolationInput(ctx, replay, &p.Replay); err != nil {
		return nil, err
	}
	p.Final, err = r.waitFixture(ctx, "fresh post-replay KeyZ barrier", func(s *assistanceFixtureState) bool {
		return len(s.Keys) > len(p.Resumed.Keys) && len(s.Releases) > len(p.Resumed.Releases) && s.Releases[len(s.Releases)-1] == "z"
	})
	if err != nil {
		return nil, err
	}
	p.AfterScreenshot, err = r.isolationScreenshot(ctx, scenario, "fresh-epoch")
	if err != nil {
		return nil, err
	}
	if _, err := r.waitIsolationProgress(ctx, request, 0); err != nil {
		return nil, err
	}
	for range 2 {
		var partial assistanceFilePartial
		if err := r.browser.call(ctx, "fileIsolationStep", map[string]any{"requestId": request}, &partial, 40*time.Second); err != nil {
			return nil, err
		}
		partial.Stage, err = r.observeIsolationStage(ctx, fixture.Name, partial.BytesSent)
		if err != nil {
			return nil, err
		}
		partial.SourcePrefixSHA256, err = isolationPrefixDigest(fixture.Path, partial.BytesSent)
		if err != nil {
			return nil, err
		}
		partial.Report, err = r.waitIsolationProgress(ctx, request, partial.BytesSent)
		if err != nil {
			return nil, err
		}
		p.Partial = append(p.Partial, partial)
	}
	var cancellation struct {
		Report json.RawMessage `json:"report"`
		Frame  []byte          `json:"cancel_frame"`
	}
	if err := r.browser.call(ctx, "fileIsolationCancel", map[string]any{"requestId": request}, &cancellation, 45*time.Second); err != nil {
		return nil, err
	}
	p.Attempt.Report = new(agentv1.AssistanceFileReport)
	if err := protojson.Unmarshal(cancellation.Report, p.Attempt.Report); err != nil {
		return nil, err
	}
	p.CancelFrame = cancellation.Frame
	p.Attempt.After, err = r.waitIsolationCleanup(ctx, fixture.Name)
	if err != nil {
		return nil, err
	}
	p.Attempt.Audit, err = r.authorizationAudit(ctx, scenario.SessionID, scenario.OperatorID, "assistance.file.cancel", request)
	if err != nil {
		return nil, err
	}
	p.RequestAudit, err = r.authorizationAudit(ctx, scenario.SessionID, scenario.OperatorID, "assistance.file.request", request)
	if err != nil {
		return nil, err
	}
	// A second real request exposes the effective remaining reservation in its
	// audit. Declining it locally neither streams bytes nor terminates assistance.
	next, err := r.fileFixture(1024, false)
	if err != nil {
		return nil, err
	}
	p.Reservation, err = r.fileUpload(ctx, scenario, next, false, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED)
	if err != nil {
		return nil, err
	}
	p.ReservationAudit, err = r.authorizationAudit(ctx, scenario.SessionID, scenario.OperatorID, "assistance.file.request", p.Reservation.Report.GetRequestId())
	if err != nil {
		return nil, err
	}
	retained, err := r.waitSession(ctx, scenario, 20*time.Second, "active session retained after stream cancellation", func(s *adminv1.AssistanceSession) bool {
		return !ended(s) && !s.GetInputState().GetPaused() && s.GetInputState().GetEpoch() >= p.Reservation.Resumed.GetEpoch()
	})
	if err != nil {
		return nil, err
	}
	p.RetainedSessionID, p.RetainedPhase, p.RetainedInput = retained.GetId(), retained.GetState(), retained.GetInputState()
	if err := verifyFileIsolation(scenario, p); err != nil {
		return nil, err
	}
	return p, nil
}

const isolationStageScript = `import os,sys,pwd,stat,json,hashlib
name=sys.argv[1]
d=os.path.join(pwd.getpwuid(os.geteuid()).pw_dir,'Downloads')
if os.path.lexists(os.path.join(d,name)): raise RuntimeError('premature_publication')
names=sorted(n for n in os.listdir(d) if n.startswith('.lindm-transfer-'))
if len(names)!=1: raise RuntimeError('ambiguous_receiver_staging')
p=os.path.join(d,names[0]); s=os.lstat(p)
if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600: raise RuntimeError('unsafe_receiver_staging')
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as f:
 a=os.fstat(f.fileno())
 if (a.st_dev,a.st_ino)!=(s.st_dev,s.st_ino): raise RuntimeError('stage_identity_changed')
 h=hashlib.sha256(); size=0
 for chunk in iter(lambda:f.read(65536),b''):
  size+=len(chunk)
  if size>32768: raise RuntimeError('unpaced_receiver')
  h.update(chunk)
 b=os.fstat(f.fileno())
 if (a.st_size,a.st_mtime_ns,a.st_ino)!=(b.st_size,b.st_mtime_ns,b.st_ino) or size!=b.st_size: raise RuntimeError('stage_changed_during_read')
print(json.dumps(dict(name=names[0],uid=s.st_uid,mode=stat.S_IMODE(s.st_mode),bytes=size,sha256=h.hexdigest(),device=s.st_dev,inode=s.st_ino)))`

func (r *assistanceRun) observeIsolationStage(ctx context.Context, name string, want uint64) (*assistanceFileStage, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		out, err := r.vm.guest.run(ctx, r.desktop.rootScript("as python3 -c "+nativeQuote(isolationStageScript)+" "+nativeQuote(name)), nil, 4096, 10*time.Second)
		if err != nil {
			return nil, err
		}
		stage := new(assistanceFileStage)
		if err := json.Unmarshal(out, stage); err != nil {
			return nil, err
		}
		if stage.Bytes == want {
			return stage, nil
		}
		if stage.Bytes > want {
			return nil, errors.New("receiver exceeded paced partial stream")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func isolationPrefixDigest(path string, count uint64) (_ string, err error) {
	if count == 0 || count > 32768 {
		return "", errors.New("partial source digest outside bound")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, int64(count)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (r *assistanceRun) waitIsolationProgress(ctx context.Context, request string, want uint64) (*agentv1.AssistanceFileReport, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		report, err := r.isolationReport(ctx, "fileIsolationState", request)
		if err != nil {
			return nil, err
		}
		if report.GetState() > agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING || report.GetBytesTransferred() > want {
			return nil, errors.New("paced transfer left the streaming state")
		}
		if report.GetState() == agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING && report.GetBytesTransferred() == want {
			return report, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (r *assistanceRun) waitIsolationCleanup(ctx context.Context, name string) (*assistanceFileObservation, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		observed, err := r.observeGuestFile(ctx, name, true)
		if err != nil {
			return nil, err
		}
		if observed.Exists {
			return nil, errors.New("cancelled partial transfer published its destination")
		}
		if len(observed.Staging) == 0 {
			return observed, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func isolationAudit(s *assistanceScenarioEvidence, a *assistanceAuditEvidence, action, request string) bool {
	return a != nil && vmValidID(a.ID) && !a.OccurredAt.IsZero() && a.ActorID == s.OperatorID && a.ResourceID == s.SessionID && a.TargetDeviceID == s.DeviceID && a.Action == action && a.Reason == "" && a.Details["request"] == request
}

func verifyIsolationInput(got assistanceFileInputProbe, want []string) error {
	if got.Channel != "lindm-input" || !got.Ordered || !slices.Equal(got.Frames, want) {
		return errors.New("isolation lacks exact genuine ordered input probes")
	}
	return nil
}

func verifyIsolationGuest(s *assistanceScenarioEvidence, baseline, next *assistanceFixtureState, keys, releases []string, clicks, pastes int) error {
	if baseline == nil || next == nil || s.LocalSession == nil || next.Backend != "GdkWaylandDisplay" || next.SessionType != "wayland" || next.UID != s.LocalSession.UID || next.SessionID != s.LocalSession.LogindSessionID || next.PID <= 0 || baseline.PID != next.PID || baseline.UID != next.UID || baseline.SessionID != next.SessionID || baseline.Display != next.Display || next.ClipboardSource == "" || next.ClipboardSource != baseline.ClipboardSource || next.Pasted != next.ClipboardSource || next.PasteSerial != baseline.PasteSerial+pastes || !reflect.DeepEqual(next.Closed, baseline.Closed) || !reflect.DeepEqual(next.Monitors, baseline.Monitors) || next.ActiveMonitors != 1 || len(next.RemovedHeads) != 0 {
		return errors.New("isolation native GTK identity, clipboard or surface changed")
	}
	if baseline.Backend != next.Backend || baseline.SessionType != next.SessionType || next.Display == "" || len(next.Monitors) != 1 || next.Monitors[0].Head != 0 || next.Monitors[0].Width <= 0 || next.Monitors[0].Height <= 0 || !isolationHex(next.ClipboardSource, 12) || baseline.Pasted != baseline.ClipboardSource {
		return errors.New("isolation lacks an independently initialized real GTK monitor and clipboard")
	}
	if len(next.Keys) != len(baseline.Keys)+len(keys) || !reflect.DeepEqual(next.Keys[:len(baseline.Keys)], baseline.Keys) || len(next.Releases) != len(baseline.Releases)+len(releases) || !slices.Equal(next.Releases[:len(baseline.Releases)], baseline.Releases) || len(next.Clicks) != len(baseline.Clicks)+clicks || !reflect.DeepEqual(next.Clicks[:len(baseline.Clicks)], baseline.Clicks) {
		return errors.New("remote input leaked, replayed or remained held across local approval")
	}
	for i, key := range keys {
		if next.Keys[len(baseline.Keys)+i].Symbol != key || next.Keys[len(baseline.Keys)+i].Head != 0 {
			return errors.New("unexpected native key during isolation")
		}
	}
	released := next.Releases[len(baseline.Releases):]
	if len(releases) == 2 {
		if !slices.Equal(released, releases) && !slices.Equal(released, []string{releases[1], releases[0]}) {
			return errors.New("missing native local paste key releases")
		}
	} else if !slices.Equal(released, releases) {
		return errors.New("missing native key releases during isolation")
	}
	return nil
}

func verifyFileIsolation(s *assistanceScenarioEvidence, p *assistanceFileIsolationProof) error {
	if s == nil || p == nil || s.Name != "files-interrupted" || !vmValidID(s.SessionID) || p.SessionID != s.SessionID || s.ExpectedCause != "operator_stopped" || (s.EndCause != "" && s.EndCause != "operator_stopped") || !s.ControlGranted {
		return errors.New("isolation proof is not bound to its ordinary operator-stopped session")
	}
	if err := verifyFileAttempt(s, p.Attempt); err != nil {
		return err
	}
	a := p.Attempt
	if a.Source.Bytes != 16<<20 || a.Report.GetDirection() != agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER || a.Report.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED || a.Report.GetReason() != "operator_cancelled" || a.Report.GetBytesTransferred() != 32768 || a.Before.Exists || a.After.Exists || a.Report.GetFile() != nil {
		return errors.New("interruption lacks bounded genuine partial cancellation without publication")
	}
	if !isolationHex(a.Source.SHA256, 32) || filepath.Base(a.Source.Path) != a.Source.Path {
		return errors.New("isolation source is not a bound private fixture")
	}
	if !strings.HasPrefix(a.Source.Path, "lindm-file-") || !strings.HasSuffix(a.Source.Path, ".txt") || !isolationHex(strings.TrimSuffix(strings.TrimPrefix(a.Source.Path, "lindm-file-"), ".txt"), 12) {
		return errors.New("isolation source lacks its private run nonce")
	}
	if p.Initial == nil || p.Initial.GetPaused() || p.Initial.GetEpoch() == 0 || a.Paused.GetEpoch() != p.Initial.GetEpoch()+1 || a.Resumed.GetEpoch() != a.Paused.GetEpoch()+1 || p.Display == "" || p.Generation == 0 {
		return errors.New("isolation lacks exact modal epoch invalidation")
	}
	if p.ApprovalX <= 0 || p.ApprovalX >= 1 || p.ApprovalY <= 0 || p.ApprovalY >= 1 || p.ApprovalX != p.ApprovalX || p.ApprovalY != p.ApprovalY {
		return errors.New("native approval pointer target is invalid")
	}
	for _, report := range []*agentv1.AssistanceFileReport{p.ModalBefore, p.ModalAfter} {
		if report.GetRequestId() != a.Report.GetRequestId() || report.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_WAITING_CONSENT || report.GetDirection() != agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER || report.GetBytesTransferred() != 0 || report.GetFile() != nil || report.GetCompletedAt() != nil {
			return errors.New("remote probes did not preserve unapproved native consent")
		}
	}
	if err := verifyIsolationInput(p.Capture, isolationFrames(p.Display, p.Generation, p.Initial.GetEpoch(), "KeyY", false)); err != nil {
		return err
	}
	if err := verifyIsolationInput(p.Hold, isolationFrames(p.Display, p.Generation, p.Initial.GetEpoch(), "ShiftLeft", true)); err != nil {
		return err
	}
	if err := verifyIsolationInput(p.Modal, isolationModalFrames(p)); err != nil {
		return err
	}
	if err := verifyIsolationInput(p.Replay, append(slices.Clone(p.Capture.Frames), isolationFrames(p.Display, p.Generation, a.Resumed.GetEpoch(), "KeyZ", false)...)); err != nil {
		return err
	}
	if p.Baseline == nil || len(p.Baseline.Keys) == 0 || p.Baseline.Keys[len(p.Baseline.Keys)-1].Symbol != "y" || len(p.Baseline.Releases) == 0 || p.Baseline.Releases[len(p.Baseline.Releases)-1] != "y" {
		return errors.New("captured stale frame never reached the native fixture before pause")
	}
	for _, check := range []struct {
		before, after  *assistanceFixtureState
		keys, releases []string
		clicks, pastes int
	}{
		{p.Baseline, p.Held, []string{"Shift_L"}, nil, 0, 0},
		{p.Held, p.Paused, nil, []string{"Shift_L"}, 0, 0},
		{p.Paused, p.Probed, []string{"Control_L", "v"}, []string{"Control_L", "v"}, 0, 1},
		{p.Probed, p.Resumed, nil, nil, 1, 0},
		{p.Resumed, p.Final, []string{"z"}, []string{"z"}, 0, 0},
	} {
		if err := verifyIsolationGuest(s, check.before, check.after, check.keys, check.releases, check.clicks, check.pastes); err != nil {
			return err
		}
	}
	for _, path := range []string{p.BeforeScreenshot, p.AfterScreenshot, p.ModalScreenshot, a.ConsentScreenshot} {
		if path == "" || !slices.Contains(s.Screenshots, path) {
			return errors.New("isolation screenshot is not scenario-bound")
		}
	}
	name := filepath.Base(a.Source.Path)
	if !fileNoticeVisible(p.ModalOCR, s.OperatorDisplay, name, false) || !fileNoticeVisible(a.ConsentOCR, s.OperatorDisplay, name, false) || p.ModalScreenshot == a.ConsentScreenshot {
		return errors.New("native approval did not remain visible before and after remote probes")
	}
	if err := verifyIsolationRefusals(s, p); err != nil {
		return err
	}
	if err := verifyIsolationPartials(s, p); err != nil {
		return err
	}
	if err := verifyIsolationReservation(s, p); err != nil {
		return err
	}
	if p.RetainedSessionID != s.SessionID || p.RetainedPhase != adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE || p.RetainedInput == nil || p.RetainedInput.GetPaused() || p.RetainedInput.GetEpoch() != p.Reservation.Resumed.GetEpoch() {
		return errors.New("stream cancellation terminated or paused the retained assistance session")
	}
	return nil
}

func verifyIsolationRefusals(s *assistanceScenarioEvidence, p *assistanceFileIsolationProof) error {
	if len(p.Refusals) != 3 || !isolationHex(p.ProbeNonce, 12) || p.ProbeNonce == p.Baseline.ClipboardSource {
		return errors.New("missing distinct modal clipboard and special-key probes")
	}
	seen := map[string]bool{}
	for i, kind := range []string{"clipboard_write", "clipboard_read", "special_keys"} {
		r := p.Refusals[i]
		if err := verifyAssistanceActor(s, r.Actor); err != nil {
			return err
		}
		if !slices.Contains(r.Actor.Permissions, "remote_assistance.clipboard") || !slices.Contains(r.Actor.Permissions, "remote_assistance.keyboard") || r.Kind != kind || !vmValidID(r.RequestID) || seen[r.RequestID] || r.Code != "failed_precondition" || r.Reason != "assistance_input_paused" || (r.HTTPStatus != 400 && r.HTTPStatus != 412) {
			return errors.New("modal refusal is not an authenticated, permitted creator's exact pause refusal")
		}
		seen[r.RequestID] = true
		action, direction := "assistance.clipboard", "operator_to_user"
		if kind == "clipboard_read" {
			direction = "user_to_operator"
		}
		if kind == "special_keys" {
			action, direction = "assistance.special_keys", ""
		}
		if !isolationAudit(s, r.Audit, action, r.RequestID) || r.Audit.Details["result"] != "denied" || r.Audit.Details["reason"] != "input_paused" || r.Audit.Details["kind"] != kind || r.Audit.Details["direction"] != direction {
			return errors.New("modal command refusal lacks its matching typed audit")
		}
		if kind == "special_keys" && r.Audit.Details["chord"] != "close_window" {
			return errors.New("special-key probe did not try to close the native window")
		}
	}
	return nil
}

func verifyIsolationPartials(s *assistanceScenarioEvidence, p *assistanceFileIsolationProof) error {
	if len(p.Partial) != 2 {
		return errors.New("interruption requires two independently observed increasing receiver writes")
	}
	request := p.Attempt.Report.GetRequestId()
	for i, partial := range p.Partial {
		want := uint64((i + 1) * 16384)
		stage := partial.Stage
		if stage == nil || s.LocalSession == nil || partial.RequestID != request || partial.Channel != "lindm-files" || !partial.Ordered || partial.BytesSent != want || stage.Bytes != want || stage.UID != s.LocalSession.UID || stage.UID == 0 || stage.Mode != 0600 || stage.Inode == 0 || !strings.HasPrefix(stage.Name, ".lindm-transfer-") || filepath.Base(stage.Name) != stage.Name || len(partial.SourcePrefixSHA256) != 64 || stage.SHA256 != partial.SourcePrefixSHA256 {
			return errors.New("partial transfer lacks private receiver bytes matching the real source prefix")
		}
		if !isolationHex(strings.TrimPrefix(stage.Name, ".lindm-transfer-"), 16) || !isolationHex(partial.SourcePrefixSHA256, 32) {
			return errors.New("receiver stage nonce or prefix digest is invalid")
		}
		frame := new(agentv1.AssistanceFileFrame)
		if len(partial.ReadyFrame) > 17<<10 || proto.Unmarshal(partial.ReadyFrame, frame) != nil || frame.GetRequestId() != request || frame.GetReady() == nil || len(frame.ProtoReflect().GetUnknown()) != 0 || len(frame.GetReady().ProtoReflect().GetUnknown()) != 0 {
			return errors.New("partial stream has no genuine receiver Ready frame")
		}
		report := partial.Report
		if report.GetRequestId() != request || report.GetDirection() != agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER || report.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING || report.GetBytesTransferred() != want || report.GetCompletedAt() != nil || report.GetFile() != nil {
			return errors.New("receiver partial write lacks matching authoritative streaming progress")
		}
	}
	first, last := p.Partial[0].Stage, p.Partial[1].Stage
	if first.Name != last.Name || first.Device != last.Device || first.Inode != last.Inode {
		return errors.New("partial writes were observed on different receiver staging files")
	}
	cancel := new(agentv1.AssistanceFileFrame)
	if len(p.CancelFrame) > 17<<10 || proto.Unmarshal(p.CancelFrame, cancel) != nil || cancel.GetRequestId() != request || cancel.GetCancel().GetReason() != "file_cancelled" || len(cancel.ProtoReflect().GetUnknown()) != 0 || len(cancel.GetCancel().ProtoReflect().GetUnknown()) != 0 {
		return errors.New("interruption lacks the helper's real stream cancellation frame")
	}
	return nil
}

func verifyIsolationReservation(s *assistanceScenarioEvidence, p *assistanceFileIsolationProof) error {
	a := p.Attempt
	request := a.Report.GetRequestId()
	for _, audit := range []struct {
		value                         *assistanceAuditEvidence
		action, result, reason, bytes string
	}{
		{p.RequestAudit, "assistance.file.request", "requested", "file_requested", "0"},
		{a.Audit, "assistance.file.cancel", "cancelled", "operator_cancelled", "32768"},
	} {
		d := audit.value
		if !isolationAudit(s, d, audit.action, request) || d.Details["direction"] != "operator_to_user" || d.Details["result"] != audit.result || d.Details["reason"] != audit.reason || d.Details["bytes"] != audit.bytes || d.Details["reserved_bytes"] != strconv.Itoa(16<<20) || d.Details["max_file_bytes"] != strconv.Itoa(16<<20) || d.Details["max_session_bytes"] != strconv.Itoa(64<<20) || d.Details["sha256"] != a.Source.SHA256 || d.Details["authorized_sha256"] != a.Source.SHA256 || d.Details["sha256_origin"] != "authorized_request" {
			return errors.New("partial cancellation refunded or misattributed its full reservation")
		}
	}
	if err := verifyFileAttempt(s, p.Reservation); err != nil {
		return fmt.Errorf("reservation successor: %w", err)
	}
	next := p.Reservation
	if next.Report.GetRequestId() == request || next.Source.Bytes != 1024 || next.Report.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED || next.Report.GetDirection() != agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER || next.Paused.GetEpoch() != a.Resumed.GetEpoch()+1 || next.Before.Exists || next.After.Exists {
		return errors.New("reservation retention was not checked with a distinct real locally declined request")
	}
	if next.ConsentScreenshot == "" || !slices.Contains(s.Screenshots, next.ConsentScreenshot) || !fileNoticeVisible(next.ConsentOCR, s.OperatorDisplay, filepath.Base(next.Source.Path), false) || next.Report.GetBytesTransferred() != 0 || next.Report.GetReason() != "file_declined" || next.Resumed.GetEpoch() != next.Paused.GetEpoch()+1 {
		return errors.New("successor reservation lacks genuine local decline and fresh input epoch")
	}
	d := p.ReservationAudit
	if !isolationAudit(s, d, "assistance.file.request", next.Report.GetRequestId()) || d.Details["reserved_bytes"] != "1024" || d.Details["max_session_bytes"] != strconv.Itoa(48<<20) || d.Details["max_file_bytes"] != strconv.Itoa(16<<20) || d.Details["sha256"] != next.Source.SHA256 || d.Details["result"] != "requested" {
		return errors.New("successor authority did not retain the cancelled upload's entire reservation")
	}
	return nil
}

func (p *assistanceFileIsolationProof) fileArtifacts() []assistanceEvidenceFile {
	if p == nil {
		return nil
	}
	var files []assistanceEvidenceFile
	for _, attempt := range []*assistanceFileAttempt{p.Attempt, p.Reservation} {
		if attempt != nil {
			files = append(files, attempt.Source)
			if attempt.Destination != nil {
				files = append(files, *attempt.Destination)
			}
		}
	}
	return files
}

func (p *assistanceFileIsolationProof) screenshotPaths() []string {
	if p == nil {
		return nil
	}
	paths := []string{p.BeforeScreenshot, p.AfterScreenshot, p.ModalScreenshot}
	for _, attempt := range []*assistanceFileAttempt{p.Attempt, p.Reservation} {
		if attempt == nil {
			continue
		}
		for _, path := range []string{attempt.ConsentScreenshot, attempt.ReceivedScreenshot, attempt.HostPickerScreenshot, attempt.GuestPickerScreenshot} {
			if path != "" {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func isolationHex(value string, bytes int) bool {
	if len(value) != bytes*2 {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

// Called by the parent's artifact replay only after its full-file SHA binding.
// Matching two claimed prefix hashes alone must not establish source identity.
func (p *assistanceFileIsolationProof) verifySourcePrefixes(dir string) error {
	if p == nil || p.Attempt == nil || filepath.Base(p.Attempt.Source.Path) != p.Attempt.Source.Path || len(p.Partial) != 2 {
		return errors.New("isolation source prefix artifacts are missing")
	}
	for _, partial := range p.Partial {
		digest, err := isolationPrefixDigest(filepath.Join(dir, p.Attempt.Source.Path), partial.BytesSent)
		if err != nil {
			return err
		}
		if digest != partial.SourcePrefixSHA256 {
			return errors.New("receiver prefix is not part of the independently rebound source artifact")
		}
	}
	return nil
}
