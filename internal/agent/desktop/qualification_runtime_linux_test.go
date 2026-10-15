// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestFixedProcessExecutableArtifactRejectsLoaderInsteadOfMainImage(t *testing.T) {
	var actual unix.Stat_t
	if err := unix.Stat("/proc/self/exe", &actual); err != nil {
		t.Fatal(err)
	}
	artifact := fixedRuntimeArtifact{path: "test executable", stat: actual}
	pid := uint32(os.Getpid())
	if err := fixedProcessExecutableArtifact(pid, artifact); err != nil {
		t.Fatalf("actual executing inode rejected: %v", err)
	}
	artifact.stat.Ino++
	if err := fixedProcessExecutableArtifact(pid, artifact); err == nil {
		t.Fatal("different executing inode accepted from a mapped-image assertion")
	}
	if err := fixedProcessExecutableArtifact(0, artifact); err == nil {
		t.Fatal("absent process accepted")
	}
}

type fakeFixedDesktopQualifier struct {
	err   error
	calls atomic.Int32
}

func (q *fakeFixedDesktopQualifier) Verify(context.Context, string, string) error {
	q.calls.Add(1)
	return q.err
}

func TestFixedDesktopNamesNeverAdmitStockTuples(t *testing.T) {
	for _, test := range []struct {
		sessionType, desktop string
		candidate, stock     *desktopProfile
	}{
		{"wayland", "Hyprland", hyprlandWayland, unlisted},
		{"x11", "X-Cinnamon", cinnamonX11Fixed, unlistedX11},
		{"wayland", "Hyprland:GNOME", nil, unlisted},
		{"wayland", "hyprland:KDE", nil, unlisted},
		{"x11", "Cinnamon", nil, unlistedX11},
		{"x11", "X-Cinnamon:GNOME", nil, unlistedX11},
		{"wayland", "X-Cinnamon", nil, unlisted},
		{"x11", "Hyprland", nil, unlistedX11},
	} {
		if got := desktopProfileFor(test.sessionType, test.desktop); got != test.stock {
			t.Fatalf("desktop name %s/%s widened stock admission: %s", test.sessionType, test.desktop, got.name)
		}
		if got := fixedDesktopProfileFor(test.sessionType, test.desktop); got != test.candidate {
			t.Fatalf("unexpected experimental candidate %s/%s: %v", test.sessionType, test.desktop, got)
		}
		deps := &sessionDeps{currentDesktop: test.desktop}
		if got, err := deps.qualifiedDesktopProfile(t.Context(), test.sessionType); err != nil || got != test.stock {
			t.Fatalf("missing verifier admitted a fixed tuple: %v, %v", got, err)
		}
	}
}

func TestFixedDesktopVerificationFailureNeverOffersConsent(t *testing.T) {
	h := newDesktopHarness(t, "Hyprland")
	q := &fakeFixedDesktopQualifier{err: errors.New("active backend is stock")}
	h.helper.deps.fixedDesktopQualifier = q
	h.sync(directiveFor(invitation(modeControl, time.Minute, 10*time.Minute)))
	report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE)
	if report.GetEndDetail() != "desktop_runtime_unqualified" || q.calls.Load() != 1 || h.portal.openCount() != 0 {
		t.Fatalf("rejected tuple reached native consent: %v calls=%d", report, q.calls.Load())
	}
	select {
	case notice := <-h.notifier.posted:
		t.Fatalf("posted %q for rejected fixed tuple", notice.notification.Summary)
	default:
	}
}

func TestQuickshellAdvertisedActionsRequireReviewedConsentSurface(t *testing.T) {
	for _, test := range []struct {
		name, desktop, sessionType string
		qualifier                  *fakeFixedDesktopQualifier
		allowPrompt                bool
	}{
		{name: "COSMIC", desktop: "COSMIC", sessionType: "wayland"},
		{name: "GNOME", desktop: "GNOME", sessionType: "wayland"},
		{name: "stock Hyprland", desktop: "Hyprland", sessionType: "wayland"},
		{name: "rejected Hyprland tuple", desktop: "Hyprland", sessionType: "wayland", qualifier: &fakeFixedDesktopQualifier{err: errors.New("unreviewed consent QML")}},
		{name: "reviewed Cinnamon tuple", desktop: "X-Cinnamon", sessionType: "x11", qualifier: &fakeFixedDesktopQualifier{}},
		{name: "reviewed Hyprland tuple", desktop: "Hyprland", sessionType: "wayland", qualifier: &fakeFixedDesktopQualifier{}, allowPrompt: true},
	} {
		for _, mode := range []agentv1.AssistanceMode{modeView, modeControl} {
			t.Run(test.name+"/"+mode.String(), func(t *testing.T) {
				h := newDesktopHarness(t, test.desktop)
				h.local.SessionType = test.sessionType
				h.local.Desktop = test.desktop
				// The actual native server reports an empty version. Only
				// reviewed source and live owner proof can admit its actions.
				h.notifier.server, h.notifier.version = "quickshell", ""
				if test.qualifier != nil {
					h.helper.deps.fixedDesktopQualifier = test.qualifier
				}
				inv := desktopInvitation(mode, func(p *agentv1.AssistancePolicy) { p.X11 = modeOn })
				h.sync(directiveFor(inv))
				if test.allowPrompt {
					h.notifier.next(t, "Remote assistance request").result <- actionDecline
					h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED)
				} else {
					report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE)
					if report.GetEndDetail() != "notification_actions_unverified" {
						t.Fatalf("unreviewed action surface was not refused precisely: %v", report)
					}
					select {
					case notice := <-h.notifier.posted:
						t.Fatalf("posted %q with unreviewed action rendering", notice.notification.Summary)
					default:
					}
				}
				if h.portal.openCount() != 0 {
					t.Fatal("portal opened without local consent")
				}
			})
		}
	}
}

func TestVerifiedFixedDesktopNarrowsCapabilitiesAndObservesLocks(t *testing.T) {
	for _, test := range []struct {
		desktop, sessionType string
		profile              *desktopProfile
	}{
		{"Hyprland", "wayland", hyprlandWayland},
		{"X-Cinnamon", "x11", cinnamonX11Fixed},
	} {
		t.Run(test.desktop, func(t *testing.T) {
			h := newDesktopHarness(t, test.desktop)
			h.local.SessionType = test.sessionType
			h.local.Desktop = test.desktop
			h.portal.grant.control = true
			q := &fakeFixedDesktopQualifier{}
			h.helper.deps.fixedDesktopQualifier = q
			inv := desktopInvitation(modeControl, func(p *agentv1.AssistancePolicy) { p.X11 = modeOn })
			directive := directiveFor(inv)
			report := h.offered(directive)
			grant := report.GetGrantedCapabilities()
			if q.calls.Load() != 1 || grant.GetDesktopProfile() != test.profile.name || grant.GetPolicy().GetKeyboard() != modeOn {
				t.Fatalf("fixed profile was not selected after proof: %v", grant)
			}
			if grant.GetPolicy().GetClipboard() != modeOff || grant.GetPolicy().GetDisplay() != modeOff || grant.GetPolicy().GetMessages() != modeOff ||
				grant.GetClipboardReason() != reasonDesktopUnqualified || grant.GetDisplayReason() != reasonDesktopUnqualified || grant.GetMessagesReason() != reasonDesktopUnqualified {
				t.Fatalf("fixed profile inherited unqualified extras: %v", grant)
			}
			h.locks.watch().locked <- lockDetailLogindLock
			h.sync(directive)
			h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED)
		})
	}
}

func TestFixedCinnamonKeepsExplicitX11PolicyGate(t *testing.T) {
	for _, test := range []struct {
		mode agentv1.AssistanceMode
		gate agentv1.AssistancePolicyMode
		want string
	}{
		{modeView, modeOff, "x11_policy_off"},
		{modeControl, modeLimited, "x11_control_not_permitted"},
		{modeView, modeLimited, ""},
		{modeControl, modeOn, ""},
	} {
		policy := fullPolicy()
		policy.X11 = test.gate
		if got := admitDesktop(cinnamonX11Fixed, test.mode, policy).refusal; got != test.want {
			t.Errorf("Cinnamon %s/%s refusal %q, want %q", test.mode, test.gate, got, test.want)
		}
	}
}

func TestFixedRuntimeMapsRequiresExecutingReviewedInode(t *testing.T) {
	artifact := unix.Stat_t{Dev: unix.Mkdev(8, 2), Ino: 42}
	for _, test := range []struct {
		line string
		want bool
	}{
		{"1000-2000 r-xp 00000000 08:02 42 /opt/reviewed.elf\n", true},
		{"1000-2000 r--p 00000000 08:02 42 /opt/reviewed.elf\n", false},
		{"1000-2000 r-xp 00000000 08:02 43 /opt/reviewed.elf\n", false},
		{"1000-2000 r-xp 00000000 08:03 42 /opt/reviewed.elf\n", false},
		{"1000-2000 r-xp 00000000 08:02 invalid /opt/reviewed.elf\n", false},
	} {
		if got := fixedMapsArtifact([]byte(test.line), artifact, nil); got != test.want {
			t.Errorf("mapping %q = %v, want %v", test.line, got, test.want)
		}
	}
}

func TestFixedRuntimeMapsAlternateStillRequiresExecutingReviewedInode(t *testing.T) {
	artifact := unix.Stat_t{Dev: unix.Mkdev(0, 29), Ino: 289965}
	const mapped = "715924f75000-71592503f000 r-xp 00013000 00:1b 289965 /opt/reviewed.elf\n"
	for _, test := range []struct {
		name string
		line string
		want bool
	}{
		{"btrfs virtual device", mapped, true},
		{"nonexecuting", strings.Replace(mapped, "r-xp", "r--p", 1), false},
		{"different inode", strings.Replace(mapped, "289965", "289966", 1), false},
		{"invalid device", strings.Replace(mapped, "00:1b", "bad:device", 1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			got := fixedMapsArtifact([]byte(test.line), artifact, func(address []byte) bool {
				called = true
				return string(address) == "715924f75000-71592503f000"
			})
			if got != test.want || called != test.want {
				t.Fatalf("matched=%v alternate called=%v, want both %v", got, called, test.want)
			}
		})
	}
	if fixedMapsArtifact([]byte(mapped), artifact, func([]byte) bool { return false }) {
		t.Fatal("accepted mismatched device without alternate kernel identity")
	}
}

func TestFixedRuntimeMapsKernelPathIdentity(t *testing.T) {
	// Exercise the real unprivileged procfs operations using this executable.
	// Changing only the snapshot's device simulates Btrfs without requiring a
	// Btrfs mount; the kernel link, mount namespace and target-root stat are real.
	path, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	var actual unix.Stat_t
	if err := unix.Stat(path, &actual); err != nil {
		t.Fatal(err)
	}
	data, err := fixedReadProc("/proc/self/maps", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	pid := uint32(os.Getpid())
	artifact := fixedRuntimeArtifact{path: path, stat: actual}
	var kernelIdentityErr error
	var mapping []byte
	inode := strconv.FormatUint(actual.Ino, 10)
	for line := range bytes.Lines(data) {
		fields := strings.Fields(string(line))
		if len(fields) < 5 || fields[4] != inode || !strings.Contains(fields[1], "x") {
			continue
		}
		kernelIdentityErr = fixedMappedArtifactPath(pid, []byte(fields[0]), artifact)
		if kernelIdentityErr != nil {
			continue
		}
		fields[3] = "ffff:ffff"
		mapping = []byte(strings.Join(fields, " ") + "\n")
		break
	}
	if mapping == nil {
		t.Fatalf("could not locate executable mapping: %v", kernelIdentityErr)
	}
	if err := fixedProcessMapsArtifactData(pid, mapping, artifact); err != nil {
		t.Fatalf("kernel identity fallback: %v", err)
	}
	for _, address := range []string{"invalid", "../exe", "xyz-2000", "1000-xyz", "2000-1000", "1000-1000"} {
		if err := fixedMappedArtifactPath(pid, []byte(address), artifact); err == nil {
			t.Fatalf("accepted invalid mapping address %q", address)
		}
	}
	artifact.path += ".not-reviewed"
	if err := fixedProcessMapsArtifactData(pid, mapping, artifact); err == nil {
		t.Fatal("accepted different kernel mapping path")
	}
	artifact.path = path
	artifact.stat.Size++
	if err := fixedProcessMapsArtifactData(pid, mapping, artifact); err == nil {
		t.Fatal("accepted changed artifact metadata")
	}
	artifact.stat = actual
	artifact.stat.Ino++
	if err := fixedProcessMapsArtifactData(pid, mapping, artifact); err == nil {
		t.Fatal("accepted different reviewed inode")
	}
}

func TestFixedRuntimeClockTicksAndProcessAge(t *testing.T) {
	for _, size := range []int{4, 8} {
		data := make([]byte, size*4)
		if size == 4 {
			binary.NativeEndian.PutUint32(data, 17)
			binary.NativeEndian.PutUint32(data[size:], 100)
		} else {
			binary.NativeEndian.PutUint64(data, 17)
			binary.NativeEndian.PutUint64(data[size:], 100)
		}
		if ticks, err := fixedAuxClockTicks(data, size); err != nil || ticks != 100 {
			t.Fatalf("AT_CLKTCK %d = %d %v", size, ticks, err)
		}
	}
	if _, err := fixedAuxClockTicks([]byte{0}, 8); err == nil {
		t.Fatal("malformed auxiliary vector accepted")
	}
	fields := append([]string{"S"}, strings.Fields(strings.Repeat("0 ", 18))...)
	fields = append(fields, "1250")
	stat := []byte("12 (name with ) spaces) " + strings.Join(fields, " "))
	got, err := fixedProcessStarted(stat, []byte("cpu 1 2 3\nbtime 1000\n"), 100)
	if err != nil || !got.Equal(time.Unix(1012, int64(500*time.Millisecond))) {
		t.Fatalf("process start = %v %v", got, err)
	}
	for _, bad := range [][]byte{nil, []byte("12 (name) S"), []byte("12 broken")} {
		if _, err := fixedProcessStarted(bad, []byte("btime 1000\n"), 100); err == nil {
			t.Fatalf("invalid process stat accepted: %q", bad)
		}
	}
}

func TestFixedFrontendSelectionRejectsOverrides(t *testing.T) {
	base := "HOME=/home/alice\x00XDG_CURRENT_DESKTOP=Hyprland\x00XDG_CONFIG_HOME=/etc/xdg\x00XDG_DATA_HOME=/usr/share\x00XDG_DATA_DIRS=/usr/share\x00"
	config, data, err := fixedPortalEnvironment([]byte(base), "Hyprland")
	if err != nil || config != "/etc/xdg" || data != "/usr/share" {
		t.Fatalf("root frontend selection: %q %q %v", config, data, err)
	}
	for _, override := range []string{
		"XDG_DESKTOP_PORTAL_DIR=/opt/other", "XDG_CONFIG_DIRS=/home/alice/config", "XDG_DATA_DIRS=/home/alice/share:/usr/share",
		"XDG_CONFIG_HOME=relative", "LD_PRELOAD=/home/alice/override.so", "XDG_CURRENT_DESKTOP=GNOME", "HOME=/another/home",
		"LD_LIBRARY_PATH=/home/alice/lib",
	} {
		t.Run(override, func(t *testing.T) {
			if _, _, err := fixedPortalEnvironment([]byte(base+override+"\x00"), "Hyprland"); err == nil {
				t.Fatalf("frontend selection override accepted: %s", override)
			}
		})
	}
	if _, _, err := fixedPortalEnvironment([]byte("HOME=/home/alice\x00"), "Hyprland"); err == nil {
		t.Fatal("frontend with absent desktop accepted")
	}
}

func TestFixedFrontendRejectsDefaultPerUserSearchHomes(t *testing.T) {
	for _, data := range []string{
		"HOME=/home/alice\x00XDG_CURRENT_DESKTOP=Hyprland\x00",
		"HOME=/home/alice\x00XDG_CURRENT_DESKTOP=Hyprland\x00XDG_CONFIG_HOME=/etc/xdg\x00XDG_DATA_HOME=/usr/share\x00",
		"HOME=/home/alice\x00XDG_CURRENT_DESKTOP=Hyprland\x00XDG_CONFIG_HOME=/etc/xdg\x00XDG_DATA_HOME=/usr/share\x00XDG_DATA_DIRS=/usr/local/share:/usr/share\x00",
	} {
		if _, _, err := fixedPortalEnvironment([]byte(data), "Hyprland"); err == nil {
			t.Fatalf("unproven user/descriptor search path accepted: %q", data)
		}
	}
}

func TestFixedFrontendPreferenceUsesActualSearchPrecedence(t *testing.T) {
	config, data := t.TempDir(), t.TempDir()
	if _, err := fixedPortalPreference(config, data, "Hyprland"); err == nil {
		t.Fatal("missing preference accepted")
	}
	for _, item := range []struct{ root, name string }{
		{data, "hyprland-portals.conf"},
		{config, "portals.conf"},
		{config, "hyprland-portals.conf"},
	} {
		dir := filepath.Join(item.root, "xdg-desktop-portal")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, item.name)
		if err := os.WriteFile(path, []byte("[preferred]\ndefault=hyprland\n"), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := fixedPortalPreference(config, data, "Hyprland")
		if err != nil || got != path {
			t.Fatalf("selected %q, want %q: %v", got, path, err)
		}
	}
}

func TestFixedDesktopConsentNeverPromisesViewOnlyDowngrade(t *testing.T) {
	for _, profile := range []*desktopProfile{hyprlandWayland, cinnamonX11Fixed} {
		s := &session{profile: profile, invitation: invitation(modeControl, time.Minute, 10*time.Minute)}
		body := s.promptNotification(false, recordingOffer{}, s.invitation.GetEffectiveCapabilities()).Body
		if strings.Contains(body, "allow viewing only") || strings.Contains(body, "every monitor") ||
			!strings.Contains(body, "selected screen together with control") || !strings.Contains(body, "no view-only choice") {
			t.Fatalf("%s control disclosure is not truthful: %q", profile.name, body)
		}
	}
}

func TestFixedServiceRejectsLoaderEnvironmentOverrides(t *testing.T) {
	if err := fixedLoaderEnvironment([]byte("HOME=/home/alice\x00LD_PRELOAD=\x00LD_AUDIT=\x00LD_LIBRARY_PATH=\x00")); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"} {
		for _, data := range []string{key + "=/home/alice/injected.so\x00", key + "=\x00" + key + "=\x00"} {
			if err := fixedLoaderEnvironment([]byte(data)); err == nil {
				t.Fatalf("service loader override admitted: %q", data)
			}
		}
	}
}
