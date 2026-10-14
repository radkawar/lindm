// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

func (r *assistanceRun) prepareFileScenario(ctx context.Context, name string) error {
	policy := assistanceFullPolicy()
	if name == "files-limited" {
		policy.Files = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	}
	if name == "files-limits" {
		policy.FileLimits.MaxFileBytes = 1024
		policy.FileLimits.MaxSessionBytes = 4096
		policy.FileLimits.AllowedMimeTypes = []string{"text/plain"}
		policy.FileLimits.AllowedExtensions = []string{".txt"}
	}
	if _, err := r.owner.Admin.UpdateAssistancePolicy(ctx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: r.deviceID, Policy: policy})); err != nil {
		return err
	}
	// QMP is the independent local-seat actor. Use an explicit native layout for
	// its literal chooser path rather than inheriting the preceding layout test.
	command := "as gsettings set org.gnome.desktop.input-sources sources " + nativeQuote("[('xkb', 'us')]") + "; as gsettings get org.gnome.desktop.input-sources sources"
	out, err := r.vm.guest.run(ctx, r.desktop.rootScript(command), nil, 4096, 15*time.Second)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "[('xkb', 'us')]" {
		return errors.New("native chooser keyboard layout was not observed as US")
	}
	return nil
}

func (r *assistanceRun) fileReport(ctx context.Context, method string, args map[string]any) (*agentv1.AssistanceFileReport, error) {
	var raw json.RawMessage
	if err := r.browser.call(ctx, method, args, &raw, 40*time.Second); err != nil {
		return nil, err
	}
	report := new(agentv1.AssistanceFileReport)
	if err := protojson.Unmarshal(raw, report); err != nil {
		return nil, fmt.Errorf("decode real browser file report: %w", err)
	}
	if !vmValidID(report.GetRequestId()) {
		return nil, errors.New("browser file report lacks authoritative request identity")
	}
	return report, nil
}

func (r *assistanceRun) waitFile(ctx context.Context, request string, state agentv1.AssistanceFileState) (*agentv1.AssistanceFileReport, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for {
		report, err := r.fileReport(ctx, "fileState", map[string]any{"requestId": request})
		if err != nil {
			return nil, err
		}
		if report.GetState() == state {
			return report, nil
		}
		if report.GetState() >= agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
			return nil, fmt.Errorf("file transfer reached %s (%s), wanted %s", report.GetState(), report.GetReason(), state)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("file transfer did not reach %s: %w", state, ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (r *assistanceRun) filePaused(ctx context.Context, scenario *assistanceScenarioEvidence, request string) (*agentv1.AssistanceInputState, error) {
	if _, err := r.waitFile(ctx, request, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_WAITING_CONSENT); err != nil {
		return nil, err
	}
	session, err := r.waitSession(ctx, scenario, 20*time.Second, "file dialog input isolation", func(session *adminv1.AssistanceSession) bool {
		return session.GetInputState().GetPaused() && session.GetInputState().GetEpoch() > 1
	})
	if err != nil {
		return nil, err
	}
	return session.GetInputState(), nil
}

func (r *assistanceRun) fileResumed(ctx context.Context, scenario *assistanceScenarioEvidence, paused *agentv1.AssistanceInputState) (*agentv1.AssistanceInputState, error) {
	session, err := r.waitSession(ctx, scenario, 20*time.Second, "new input epoch after local file decision", func(session *adminv1.AssistanceSession) bool {
		return !session.GetInputState().GetPaused() && session.GetInputState().GetEpoch() > paused.GetEpoch()
	})
	if err != nil {
		return nil, err
	}
	return session.GetInputState(), nil
}

func fileNoticeVisible(text, operator, name string, completed bool) bool {
	normalize := func(value string) string { return strings.Join(strings.Fields(strings.ToLower(value)), " ") }
	text = normalize(text)
	title := "receive a file from your support operator"
	if completed {
		title = "lindm file received"
	}
	// GNOME wraps a long file name at its hyphen ("lindm-file-\nf3fc…txt",
	// layers-fedora44-files-04), so the name is compared on letters and
	// digits only, with tesseract's 1/l/i and 0/o confusions folded on both
	// sides ("fe6elffcO79…" for "fe6e1ffc079…", layers-fedora44-files-07).
	// Tesseract also inserts glyphs into the hex name ("1l" for "1", "a/7"
	// for "a7", "O0" for "0", "8972" for "892": layers-fedora44-files-11,
	// -15, -17), so up to fileNameOCREdits edits are tolerated; a different
	// random name differs in most of its 24 hex digits.
	return strings.Contains(text, title) && strings.Contains(text, normalize(operator)) && ocrContainsApprox(ocrAlnum(text), ocrAlnum(name), fileNameOCREdits) && strings.Contains(text, "downloads")
}

// fileNameOCREdits bounds the insertions, deletions and substitutions
// tolerated in an OCR'd file name.
const fileNameOCREdits = 3

// fileIncomingDecision reads and binds the compositor's actual notification
// pixels before making the independent local-seat approval/decline click.
// GNOME shows one banner at a time: the consent can wait behind the
// remote-control "in progress" notice posted at activation
// (layers-fedora44-files-02), so another notice is read, bound and nudged
// away as local activity until the consent itself is shown.
func (r *assistanceRun) fileIncomingDecision(ctx context.Context, scenario *assistanceScenarioEvidence, request, name string, allow bool) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for attempt := 0; ; attempt++ {
		image, banner, err := r.screen.waitBanner(ctx, 30*time.Second)
		if err != nil {
			return "", "", err
		}
		path, err := r.screen.save(fmt.Sprintf("%s-%s-file-consent-%02d", scenario.Name, request, attempt), image)
		if err != nil {
			return "", "", err
		}
		scenario.Screenshots = append(scenario.Screenshots, path)
		text, err := r.bannerOCR(ctx, path, image, banner)
		if err != nil {
			return "", "", err
		}
		if fileNoticeVisible(string(text), scenario.OperatorDisplay, name, false) {
			action := 1
			if allow {
				action = 0
			}
			// Save, Decline, then the indicator's Stop.
			if err := r.screen.click(ctx, image.Bounds(), notificationActionPoint(banner, 3, action), "file-local-consent", scenario); err != nil {
				return "", "", err
			}
			return path, string(text), nil
		}
		if err := r.screen.nudge(ctx, image.Bounds(), attempt); err != nil {
			return "", "", err
		}
		select {
		case <-ctx.Done():
			return "", "", fmt.Errorf("incoming file consent text is not visible in the guest screenshots: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

func (r *assistanceRun) fileReceivedNotice(ctx context.Context, scenario *assistanceScenarioEvidence, request, name string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for attempt := range 30 {
		image, banner, err := r.screen.waitBanner(ctx, 15*time.Second)
		if err != nil {
			return "", "", err
		}
		path, err := r.screen.save(fmt.Sprintf("%s-%s-file-received-%02d", scenario.Name, request, attempt), image)
		if err != nil {
			return "", "", err
		}
		scenario.Screenshots = append(scenario.Screenshots, path)
		text, err := r.bannerOCR(ctx, path, image, banner)
		if err != nil {
			return "", "", err
		}
		if fileNoticeVisible(string(text), scenario.OperatorDisplay, name, true) {
			return path, string(text), nil
		}
		// The old consent banner can still be fading out, or another notice
		// is shown ahead of it. Read actual compositor pixels, nudging as
		// local activity, until the independently identifiable completion
		// notification appears.
		if err := r.screen.nudge(ctx, image.Bounds(), attempt); err != nil {
			return "", "", err
		}
		select {
		case <-ctx.Done():
			return "", "", fmt.Errorf("completed Downloads notification was not observed: %w", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
	return "", "", errors.New("completed Downloads notification is not visible in the guest screenshots")
}
