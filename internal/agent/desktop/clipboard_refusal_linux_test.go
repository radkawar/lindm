//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestClipboardRefusalClassifiesOnlyExplicitOptionalFailures(t *testing.T) {
	for name, want := range map[string]string{
		"org.freedesktop.DBus.Error.UnknownMethod":    "portal_clipboard_unsupported",
		"org.freedesktop.DBus.Error.UnknownInterface": "portal_clipboard_unsupported",
		"org.freedesktop.DBus.Error.NotSupported":     "portal_clipboard_unsupported",
		"org.freedesktop.portal.Error.NotSupported":   "portal_clipboard_unsupported",
		"org.freedesktop.portal.Error.NotAllowed":     "portal_clipboard_denied",
		// Upstream RequestClipboard uses these for invalid session/type/state.
		"org.freedesktop.DBus.Error.AccessDenied":      "",
		"org.freedesktop.DBus.Error.Failed":            "",
		"org.freedesktop.portal.Error.Failed":          "",
		"org.freedesktop.portal.Error.InvalidArgument": "",
		"org.freedesktop.DBus.Error.UnknownObject":     "",
		"org.freedesktop.DBus.Error.NoReply":           "",
		"org.freedesktop.DBus.Error.Timeout":           "",
		"org.freedesktop.DBus.Error.Disconnected":      "",
		"org.freedesktop.DBus.Error.ServiceUnknown":    "",
		"org.freedesktop.DBus.Error.NameHasNoOwner":    "",
		"org.freedesktop.portal.Error.Cancelled":       "",
	} {
		for _, err := range []error{dbus.Error{Name: name}, &dbus.Error{Name: name}, fmt.Errorf("method failed: %w", &dbus.Error{Name: name})} {
			if got := clipboardRequestRefusal(err); got != want {
				t.Fatalf("%s = %q, want %q", name, got, want)
			}
		}
	}
	for _, err := range []error{nil, context.Canceled, context.DeadlineExceeded, ErrPortalCancelled, errors.New("org.freedesktop.DBus.Error.NotSupported")} {
		if got := clipboardRequestRefusal(err); got != "" {
			t.Fatalf("ambiguous/local error %v became refusal %q", err, got)
		}
	}
}

func TestClipboardStartCannotGrantWithoutSuccessfulPriorRequest(t *testing.T) {
	for _, reason := range []string{"", "portal_clipboard_unsupported", "portal_clipboard_denied"} {
		// No bus: a forbidden native selection call would fail this test rather
		// than being echoed by a mock clipboard implementation.
		grant := &portalGrant{clipboardReason: reason}
		grant.startClipboard(map[string]dbus.Variant{"clipboard_enabled": dbus.MakeVariant(true)})
		if grant.clipboard != nil || grant.ClipboardGranted() {
			t.Fatal("Start alone manufactured clipboard authority")
		}
		if err := grant.ClipboardWrite(t.Context(), "must not become a selection", time.Now().Add(time.Second)); err == nil {
			t.Fatal("unrequested clipboard write accepted")
		}
		if text, err := grant.ClipboardRead(t.Context()); err == nil || text != "" {
			t.Fatal("unrequested clipboard read accepted")
		}
	}
}

func TestClipboardRequestRequiresExactStartGrantBeforeProcessingSignals(t *testing.T) {
	for name, results := range map[string]map[string]dbus.Variant{
		"missing":    {},
		"false":      {"clipboard_enabled": dbus.MakeVariant(false)},
		"wrong type": {"clipboard_enabled": dbus.MakeVariant(uint32(1))},
		"granted":    {"clipboard_enabled": dbus.MakeVariant(true)},
	} {
		t.Run(name, func(t *testing.T) {
			bus := &SessionBus{done: make(chan struct{}), watches: make(map[*busWatch]struct{})}
			grant := &portalGrant{bus: bus, closed: make(chan struct{})}
			ctx, cancel := context.WithCancel(t.Context())
			pending := &portalClipboard{grant: grant, ctx: ctx, cancel: cancel,
				events: &busWatch{bus: bus, signals: make(chan *dbus.Signal), overflow: make(chan struct{})}}
			grant.clipboard = pending // A successful RequestClipboard, still ungranted.
			if grant.ClipboardGranted() {
				t.Fatal("request alone granted clipboard")
			}
			grant.startClipboard(results)
			if name == "granted" {
				if !grant.ClipboardGranted() || pending.done == nil {
					t.Fatal("exact request+Start grant not enabled")
				}
				pending.close()
			} else {
				if grant.clipboard != nil || pending.done != nil || grant.ClipboardGranted() {
					t.Fatal("ungranted clipboard worker survived Start")
				}
				if pending.ctx.Err() == nil {
					t.Fatal("ungranted pending clipboard lifetime not cancelled")
				}
				if grant.ClipboardReason() != "portal_clipboard_not_granted" {
					t.Fatal("Start denial lacks explicit reason")
				}
				if err := grant.ClipboardWrite(t.Context(), "private", time.Now().Add(time.Second)); err == nil {
					t.Fatal("Start denial allowed selection creation")
				}
			}
		})
	}
}

func TestIndependentClipboardRefusalPreservesOtherConsentedCapabilities(t *testing.T) {
	for _, reason := range []string{"portal_clipboard_unsupported", "portal_clipboard_denied"} {
		grant := &portalGrant{control: true, keyboard: true, clipboardReason: reason, streams: []Stream{{ID: "monitor-1"}, {ID: "monitor-2"}}}
		policy := tierOneInvitation(modeControl).GetRequestedCapabilities()
		caps := grantedCapabilities(policy, grant)
		if caps.GetPolicy().GetClipboard() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF || caps.GetClipboardReason() != reason {
			t.Fatal("native refusal not reported independently")
		}
		if caps.GetPolicy().GetKeyboard() != policy.GetKeyboard() || caps.GetPolicy().GetDisplay() != policy.GetDisplay() || caps.GetPolicy().GetMessages() != policy.GetMessages() {
			t.Fatal("optional clipboard refusal revoked unrelated consented capabilities")
		}
		policy.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
		if got := grantedCapabilities(policy, grant).GetClipboardReason(); got != "not_requested_or_allowed" {
			t.Fatalf("native status overrode prior product consent: %s", got)
		}
	}
}
