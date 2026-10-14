// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"lindm/internal/platform"
)

// gdmSysconfigAutologin names user (a shell word) as DISPLAYMANAGER_AUTOLOGIN
// in the session's GDM sysconfig file, rewriting the file in place (inode and
// SELinux label kept) and leaving its other settings. Without a declared file
// it is empty.
func gdmSysconfigAutologin(session platform.LabSession, user string) string {
	if session.GDMSysconfig == "" {
		return ""
	}
	file := nativeQuote(session.GDMSysconfig)
	return `settings=$(grep -v '^DISPLAYMANAGER_AUTOLOGIN=' ` + file + ` 2>/dev/null || true)
{ if test -n "$settings"; then printf '%s\n' "$settings"; fi; printf 'DISPLAYMANAGER_AUTOLOGIN="%s"\n' ` + user + `; } > ` + file + `
`
}

// gdmSysconfigLabel is the GDM sysconfig file as an extra restorecon operand.
func gdmSysconfigLabel(session platform.LabSession) string {
	if session.GDMSysconfig == "" {
		return ""
	}
	return " " + nativeQuote(session.GDMSysconfig)
}

const actionDesktopUser = "lindm-desktop-test"

// labDesktop is one installer desktop's lab session profile, keyed by the
// encrypted golden's desktop variant: how the lab user is logged in, which
// native oracle reports the desktop locker's state and whether that locker
// reports to logind. Release facts (display-manager files, session name,
// terminal, capture packages) come from the release's platform.LabSession.
type labDesktop struct {
	// name is the encrypted installer desktop variant.
	name string
	// autologin configures the display manager to log "$u" in and restarts
	// it; it runs as root after the user exists.
	autologin func(platform.LabSession) string
	// services are the logind Service values of the autologin session.
	services []string
	// sessionTypes are the accepted logind session types.
	sessionTypes []string
	// userEnv is the display environment for commands in the user session.
	userEnv string
	// ready exits zero (inside the user prelude) once the desktop started.
	ready string
	// quiet disables idle blanking and automatic lock in the lab session.
	quiet string
	// lockOracle prints "locked" or "unlocked" from the desktop's own locker.
	lockOracle string
	// locker names the native oracle in records.
	locker string
	// lockedHint: the locker sets logind LockedHint.
	lockedHint bool
	// logindLock: logind's Session.Lock reaches the locker.
	logindLock bool
	// assistance are the scenarios that natively hold on this desktop.
	assistance []assistanceScenarioSpec
}

// labDesktops are the natively observed desktop profiles.
var labDesktops = []*labDesktop{
	{
		name: "gnome",
		autologin: func(session platform.LabSession) string {
			return `printf '[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=%s\nInitialSetupEnable=False\n' "$u" > ` + nativeQuote(session.GDMConfig) + `
` + gdmSysconfigAutologin(session, `"$u"`) + `install -d -m 0755 /var/lib/AccountsService/users
printf '[User]\nSystemAccount=false\nSession=%s\nXSession=%s\n' ` + nativeQuote(session.Name) + ` ` + nativeQuote(session.Name) + ` > /var/lib/AccountsService/users/"$u"
if command -v restorecon >/dev/null; then restorecon -RF ` + nativeQuote(session.GDMConfig) + gdmSysconfigLabel(session) + ` /var/lib/AccountsService /home/"$u"; fi
systemctl restart display-manager.service`
		},
		services:     []string{"gdm-autologin"},
		sessionTypes: []string{"wayland", "x11"},
		userEnv:      "WAYLAND_DISPLAY=wayland-0",
		// gnome-session reaches its running phase only after the shell
		// finished startup, which is when GNOME 50 opens its login overview.
		ready: `as gdbus call --session --dest org.gnome.SessionManager --object-path /org/gnome/SessionManager --method org.gnome.SessionManager.IsSessionRunning | grep -q true`,
		quiet: `as gsettings set org.gnome.desktop.session idle-delay 0
as gsettings set org.gnome.desktop.screensaver lock-enabled false
as gsettings set org.gnome.settings-daemon.plugins.power idle-dim false
as gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type nothing
as gsettings set org.gnome.shell welcome-dialog-last-shown-version 999
pkill -u "$u" -x gnome-tour || true`,
		lockOracle: `pgrep -u "$uid" -x gnome-shell >/dev/null
case "$(as gdbus call --session --dest org.gnome.ScreenSaver --object-path /org/gnome/ScreenSaver --method org.gnome.ScreenSaver.GetActive)" in
"(true,)") echo locked;; "(false,)") echo unlocked;; *) echo invalid;; esac`,
		locker:     "gnome-shell org.gnome.ScreenSaver.GetActive",
		lockedHint: true,
		logindLock: true,
		assistance: assistanceScenarios,
	},
	{
		// LightDM autologin into the X11 Cinnamon session (Linux Mint 22.3);
		// cinnamon-screensaver locks on logind Session.Lock but never calls
		// SetLockedHint.
		name: "cinnamon",
		autologin: func(session platform.LabSession) string {
			return `install -d -m 0755 /etc/lightdm/lightdm.conf.d
printf '[Seat:*]\nautologin-user=%s\nautologin-user-timeout=0\nautologin-session=%s\n' "$u" ` + nativeQuote(session.Name) + ` > /etc/lightdm/lightdm.conf.d/95-lindm-desktop-test.conf
install -d -m 0755 /var/lib/AccountsService/users
printf '[User]\nSystemAccount=false\nSession=%s\nXSession=%s\n' ` + nativeQuote(session.Name) + ` ` + nativeQuote(session.Name) + ` > /var/lib/AccountsService/users/"$u"
systemctl restart display-manager.service`
		},
		services:     []string{"lightdm-autologin"},
		sessionTypes: []string{"x11"},
		userEnv:      `DISPLAY=:0 XAUTHORITY=/home/$u/.Xauthority`,
		ready:        `as gdbus call --session --dest org.cinnamon.ScreenSaver --object-path /org/cinnamon/ScreenSaver --method org.freedesktop.DBus.Peer.Ping >/dev/null && as gdbus call --session --dest org.Cinnamon --object-path /org/Cinnamon --method org.freedesktop.DBus.Peer.Ping >/dev/null`,
		quiet: `as gsettings set org.cinnamon.desktop.session idle-delay 0
as gsettings set org.cinnamon.desktop.screensaver lock-enabled false
as gsettings set org.cinnamon.settings-daemon.plugins.power sleep-inactive-ac-timeout 0
pkill -u "$u" -x mintwelcome || true`,
		lockOracle: `pgrep -u "$uid" -x cinnamon >/dev/null
case "$(as gdbus call --session --dest org.cinnamon.ScreenSaver --object-path /org/cinnamon/ScreenSaver --method org.cinnamon.ScreenSaver.GetActive)" in
"(true,)") echo locked;; "(false,)") echo unlocked;; *) echo invalid;; esac`,
		locker:     "cinnamon-screensaver org.cinnamon.ScreenSaver.GetActive",
		lockedHint: false,
		logindLock: true,
		// xdg-desktop-portal-xapp and -gtk implement no ScreenCast or
		// RemoteDesktop; lindm has no X11 capture path, so both modes end
		// UNAVAILABLE before consent.
		assistance: unavailableScenarios("portal_screencast_unavailable", "portal_screencast_unavailable"),
	},
	{
		// SDDM autologin into the uwsm-managed Hyprland session (Omarchy 4).
		// Omarchy installs its shell (Quickshell lock, notifications) as the
		// install user's configuration; the lab user receives a copy of it.
		// The Quickshell WlSessionLock never listens to logind Session.Lock
		// and never sets LockedHint.
		name: "hyprland",
		autologin: func(session platform.LabSession) string {
			return `owner=$(getent passwd 1000 | cut -d: -f6)
for d in .config .local; do if test -d "$owner/$d"; then cp -a "$owner/$d" /home/"$u"/; fi; done
chown -R "$u":"$u" /home/"$u"
install -d -m 0755 /etc/sddm.conf.d
printf '[Autologin]\nUser=%s\nSession=%s\nRelogin=false\n' "$u" ` + nativeQuote(session.Name+".desktop") + ` > /etc/sddm.conf.d/zz-lindm-desktop-test.conf
systemctl restart display-manager.service`
		},
		services:     []string{"sddm-autologin"},
		sessionTypes: []string{"wayland"},
		userEnv:      `WAYLAND_DISPLAY=$(cd /run/user/$uid && ls -d wayland-? | head -1) HYPRLAND_INSTANCE_SIGNATURE=$(ls /run/user/$uid/hypr | head -1)`,
		ready:        `pgrep -u "$uid" -x Hyprland >/dev/null && as hyprctl -j monitors >/dev/null`,
		quiet:        `pkill -u "$u" -x hypridle || true`,
		// omarchy-hyprland-session-locked is Omarchy's own oracle: exit 0 when
		// the compositor holds an ext-session-lock, 1 when not.
		lockOracle: `pgrep -u "$uid" -x Hyprland >/dev/null
if as omarchy-hyprland-session-locked; then echo locked; else case $? in 1) echo unlocked;; *) echo invalid;; esac; fi`,
		locker:     "Omarchy Quickshell WlSessionLock via omarchy-hyprland-session-locked",
		lockedHint: false,
		logindLock: false,
		// xdg-desktop-portal-hyprland implements ScreenCast but no
		// RemoteDesktop, and a lock there neither reaches logind nor stops
		// screencopy, so VIEW is refused for its unobservable lock and CONTROL
		// for its missing portal, both before consent.
		assistance: unavailableScenarios("session_lock_state_unreported", "portal_remote_desktop_unavailable"),
	},
	{
		// greetd's initial_session autologin into start-cosmic (Pop!_OS 24.04).
		// cosmic-greeter never sets LockedHint, but it locks on logind
		// Session.Lock and PrepareForSleep, and Super+Escape runs `loginctl
		// lock-session`; its own log lines are the native lock oracle.
		name: "cosmic",
		// greetd starts an initial_session without the environment
		// cosmic-greeter passes on a real login (XDG_SESSION_TYPE=wayland,
		// XDG_SESSION_DESKTOP, XDG_CURRENT_DESKTOP; cosmic-greeter greeter.rs),
		// so logind registered it as Type=tty (pop2404-lock-quarantine-02).
		// Pop's greetd ignores initial_session.service (it opened the session
		// with the cosmic-greeter PAM service; pop2404-lock-quarantine-dbg-01),
		// so pam_env in that service supplies exactly that environment. The
		// greeter's own sessions run COSMIC Wayland too. The locker logs its
		// "session locked"/"session unlocked" oracle lines at info, under a
		// default warn filter (cosmic-greeter locker.rs), so the session
		// raises only that crate to info (pop2404-lock-quarantine-dbg-02).
		autologin: func(platform.LabSession) string {
			return `printf 'XDG_SESSION_TYPE=wayland\nXDG_SESSION_DESKTOP=cosmic\nXDG_CURRENT_DESKTOP=COSMIC\nRUST_LOG=warn,cosmic_greeter=info\n' > /etc/lindm-lab-cosmic-session.env
pam=/etc/pam.d/cosmic-greeter
if ! grep -q lindm-lab-cosmic-session.env "$pam"; then
  { printf 'session required pam_env.so readenv=1 user_readenv=0 envfile=/etc/lindm-lab-cosmic-session.env\n'; cat "$pam"; } > "$pam.lindm"
  chmod --reference="$pam" "$pam.lindm"
  mv "$pam.lindm" "$pam"
fi
config=/etc/greetd/cosmic-greeter.toml
awk 'BEGIN{skip=0} /^\[/{skip=($0=="[initial_session]")} !skip' "$config" > "$config.lindm"
printf '\n[initial_session]\ncommand = "start-cosmic"\nuser = "%s"\n' "$u" >> "$config.lindm"
chmod --reference="$config" "$config.lindm"
mv "$config.lindm" "$config"
install -d -o "$u" -g "$u" -m 0700 /home/"$u"/.config/cosmic/com.system76.CosmicIdle/v1
printf 'None' > /home/"$u"/.config/cosmic/com.system76.CosmicIdle/v1/screen_off_time
printf 'None' > /home/"$u"/.config/cosmic/com.system76.CosmicIdle/v1/suspend_on_ac_time
chown -R "$u":"$u" /home/"$u"/.config/cosmic
runfile=$(sed -n 's/^runfile *= *"\(.*\)"/\1/p' "$config")
systemctl stop display-manager.service
# greetd runs initial_session only on its first run of a boot.
rm -f "${runfile:-/run/greetd.run}"
systemctl start display-manager.service`
		},
		services:     []string{"cosmic-greeter"},
		sessionTypes: []string{"wayland"},
		userEnv:      `WAYLAND_DISPLAY=$(cd /run/user/$uid && ls -d wayland-? | head -1)`,
		ready:        `pgrep -u "$uid" -x cosmic-comp >/dev/null && pgrep -u "$uid" -x cosmic-panel >/dev/null`,
		quiet:        `pkill -u "$u" -f cosmic-initial-setup || true`,
		// cosmic-greeter's locker logs "session locked" once its lock surfaces
		// are shown and "session unlocked" when it releases them.
		lockOracle: `pgrep -u "$uid" -x cosmic-comp >/dev/null
last=$(journalctl -b _UID="$uid" -o cat --no-pager | grep -E 'session (locked|unlocked)' | tail -n 1 || true)
case "$last" in *"session unlocked"*|"") echo unlocked;; *"session locked"*) echo locked;; *) echo invalid;; esac`,
		locker:     "cosmic-greeter locker journal (session locked/unlocked)",
		lockedHint: false,
		logindLock: true,
		// cosmic-notifications (0.1.0 and 1.10.0) shows the consent prompt without its
		// Allow/Decline buttons (pop2404-assistance-04), so VIEW is refused
		// before consent. xdg-desktop-portal-cosmic 0.1.0pop1 has no
		// RemoteDesktop, which refuses CONTROL first.
		assistance: unavailableScenarios("notification_actions_hidden", "portal_remote_desktop_unavailable"),
	},
}

// labDesktopFor returns the profile of the golden's desktop variant, which
// the release's lab session must install.
func labDesktopFor(name string, release *platform.Release) (*labDesktop, error) {
	if _, ok := release.Lab.Session.Desktops[name]; !ok {
		return nil, fmt.Errorf("lab desktop %q is not a maintained lab session of %s", name, release.Name)
	}
	for _, desktop := range labDesktops {
		if desktop.name == name {
			return desktop, nil
		}
	}
	return nil, fmt.Errorf("no lab desktop profile %q", name)
}

// rootScript runs script as root with the user prelude: u, uid and as(), which
// runs a command inside the autologin user's manager, bus and display. Only
// the disposable lab overlay is touched.
func (d *labDesktop) rootScript(script string) string {
	return "sudo -n sh -eu -c " + nativeQuote(`u=`+actionDesktopUser+`
uid=$(id -u "$u")
as() { sudo -n -u "$u" env XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus `+d.userEnv+` "$@"; }
`+script)
}

// lockState is one expected native lock observation.
type lockState struct {
	// hint is logind's LockedHint; locker the desktop locker's own state.
	hint, locker bool
}

// expectedLock is what the desktop natively shows before any lock, or after
// logind LockSessions or lock-session reached it.
func (d *labDesktop) expectedLock(locked bool) lockState {
	if !locked {
		return lockState{}
	}
	return lockState{hint: d.lockedHint, locker: d.logindLock}
}

type actionDesktopEvidence struct {
	SessionID  string `json:"session_id"`
	Type       string `json:"type"`
	Class      string `json:"class"`
	User       string `json:"user"`
	Service    string `json:"service"`
	Desktop    string `json:"desktop"`
	LockedHint bool   `json:"locked_hint"`
	// ScreenSaverActive is the desktop locker's own state from Locker.
	ScreenSaverActive bool   `json:"screen_saver_active"`
	Locker            string `json:"locker"`
}

// prepareActionDesktop changes only the disposable overlay. A password-enabled
// user is required: a locked/passwordless installer SSH account is not a useful
// lock-screen fixture. The display manager performs the real PAM/logind login.
func prepareActionDesktop(ctx context.Context, vm *EncryptedVM, desktop *labDesktop, release *platform.Release) (string, error) {
	initial, err := vm.Run(ctx, `sudo -n sh -eu -c 'loginctl list-sessions --no-legend --no-pager | while read -r id rest; do loginctl show-session "$id" -p Id -p Name -p Class -p Type -p Desktop -p Service -p LockedHint; done'`, nil)
	if err != nil {
		return "", err
	}
	script := `set -eu
u=` + actionDesktopUser + `
useradd --create-home --shell /bin/bash "$u"
chpasswd
install -d -o "$u" -g "$u" -m 0700 /home/"$u"/.config
printf 'yes\n' > /home/"$u"/.config/gnome-initial-setup-done
chown "$u":"$u" /home/"$u"/.config/gnome-initial-setup-done
`
	for _, marker := range release.Lab.Session.FirstLoginMarkers {
		path := filepath.Join("/home", actionDesktopUser, ".config", marker)
		script += `install -d -o "$u" -g "$u" -m 0700 ` + nativeQuote(filepath.Dir(path)) + "\n"
		script += `install -o "$u" -g "$u" -m 0600 /dev/null ` + nativeQuote(path) + "\n"
	}
	script += desktop.autologin(release.Lab.Session)
	password := []byte(actionDesktopUser + ":" + rand.Text() + "\n")
	defer clear(password)
	_, err = vm.Run(ctx, "sudo -n sh -eu -c "+nativeQuote(script), bytes.NewReader(password))
	return string(initial), err
}

func observeActionDesktop(ctx context.Context, vm *EncryptedVM, desktop *labDesktop, want lockState) (*actionDesktopEvidence, error) {
	data, err := vm.Run(ctx, desktop.rootScript(`loginctl list-sessions --no-legend --no-pager | while read -r id rest; do
 type=$(loginctl show-session "$id" -p Type --value)
 case "$type" in x11|wayland) ;; *) continue;; esac
 class=$(loginctl show-session "$id" -p Class --value)
 [ "$class" = user ] || continue
 user=$(loginctl show-session "$id" -p Name --value)
 [ "$user" = "$u" ] || continue
 printf "%s\n%s\n" "$id" "$type"
 loginctl show-session "$id" -p Desktop --value
 loginctl show-session "$id" -p LockedHint --value
 printf "%s\n%s\n" "$class" "$user"
 loginctl show-session "$id" -p Service --value
`+desktop.lockOracle+`
 exit 0
done`), nil)
	if err != nil {
		return nil, err
	}
	return parseActionDesktop(desktop, data, want)
}

func parseActionDesktop(desktop *labDesktop, data []byte, want lockState) (*actionDesktopEvidence, error) {
	fields := strings.Split(strings.TrimSpace(string(data)), "\n")
	// logind's Desktop label can be empty, even with a real GNOME session.
	// The user-owned desktop process and its locker API establish the desktop.
	if len(fields) != 8 || !slices.Contains(desktop.sessionTypes, fields[1]) || fields[4] != "user" || fields[5] != actionDesktopUser || !slices.Contains(desktop.services, fields[6]) {
		return nil, fmt.Errorf("actual %s user session was not observed: %q", desktop.name, fields)
	}
	if fields[3] != "yes" && fields[3] != "no" {
		return nil, errors.New("invalid logind lock observation")
	}
	if fields[7] != "locked" && fields[7] != "unlocked" {
		return nil, fmt.Errorf("invalid %s locker observation", desktop.name)
	}
	observed := &actionDesktopEvidence{SessionID: fields[0], Type: fields[1], Desktop: fields[2], Class: fields[4], User: fields[5], Service: fields[6], LockedHint: fields[3] == "yes", ScreenSaverActive: fields[7] == "locked", Locker: desktop.locker}
	if observed.LockedHint != want.hint || observed.ScreenSaverActive != want.locker {
		return nil, fmt.Errorf("native logind LockedHint=%t and %s locker=%t did not reach expectation %+v", observed.LockedHint, desktop.name, observed.ScreenSaverActive, want)
	}
	return observed, nil
}

func waitActionDesktop(ctx context.Context, vm *EncryptedVM, desktop *labDesktop, want lockState) (*actionDesktopEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last error
	for {
		result, err := observeActionDesktop(ctx, vm, desktop, want)
		if err == nil {
			return result, nil
		}
		if ctx.Err() != nil && last != nil {
			return nil, fmt.Errorf("desktop state deadline (last completed observation: %v): %w", last, err)
		}
		last = err
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("desktop state deadline: %w", last)
		case <-ticker.C:
		}
	}
}
