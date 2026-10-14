// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func quarantineTable(actionID string) (string, error) {
	compact := strings.ReplaceAll(actionID, "-", "")
	if len(compact) != 32 || strings.IndexFunc(compact, func(r rune) bool { return (r < '0' || r > '9') && (r < 'a' || r > 'f') }) != -1 {
		return "", ErrConflict
	}
	return "lindm_q_" + compact, nil
}

// The active set element expires inside the kernel, independently of executor
// lifetime, open connections, wall-clock steps, or a process-local timer. An empty
// set makes the terminal drop rule stop matching. Rules are never persisted across
// reboot. No packet updates the element and therefore traffic cannot extend it.
// Native syntax references: https://netfilter.org/projects/nftables/manpage.html
// and https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts.
func quarantineRules(table string, endpoints, dns []string, seconds uint32) ([]byte, error) {
	var rules strings.Builder
	// integer alone has no fixed width and nft rejects it as a set key. Derive
	// the exact key type from the same numgen expression used by every lookup.
	fmt.Fprintf(&rules, "add table inet %s\nadd set inet %s active { typeof numgen inc mod 1; flags timeout; timeout %ds; elements = { 0 timeout %ds }; }\n", table, table, seconds, seconds)
	for _, direction := range []string{"input", "output"} {
		fmt.Fprintf(&rules, "add chain inet %s %s { type filter hook %s priority -10; policy accept; }\n", table, direction, direction)
		address := "daddr"
		if direction == "input" {
			address = "saddr"
		}
		for _, endpoint := range endpoints {
			ip, err := netip.ParseAddr(endpoint)
			if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
				return nil, ErrUnsupported
			}
			family := "ip"
			if ip.Is6() {
				family = "ip6"
			}
			fmt.Fprintf(&rules, "add rule inet %s %s %s %s %s accept\n", table, direction, family, address, ip.String())
		}
		for _, server := range dns {
			ip, err := netip.ParseAddr(server)
			if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
				return nil, ErrUnsupported
			}
			family, port := "ip", "dport"
			if ip.Is6() {
				family = "ip6"
			}
			if direction == "input" {
				port = "sport"
			}
			for _, protocol := range []string{"udp", "tcp"} {
				fmt.Fprintf(&rules, "add rule inet %s %s %s %s %s %s %s 53 accept\n", table, direction, family, address, ip.String(), protocol, port)
			}
		}
		fmt.Fprintf(&rules, "add rule inet %s %s numgen inc mod 1 @active drop\n", table, direction)
	}
	// Forwarded traffic must not provide an unfiltered alternate egress path.
	fmt.Fprintf(&rules, "add chain inet %s forward { type filter hook forward priority -10; policy accept; }\nadd rule inet %s forward numgen inc mod 1 @active drop\n", table, table)
	return []byte(rules.String()), nil
}

func (p *Provider) quarantineTables(ctx context.Context) (map[string]bool, error) {
	out, err := p.run(ctx, nativeRequest{command: nft, args: []string{"--json", "list", "tables"}})
	if err != nil {
		return nil, err
	}
	var document struct {
		NFTables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &document); err != nil {
		return nil, err
	}
	result := make(map[string]bool)
	for _, entry := range document.NFTables {
		if entry.Table != nil && entry.Table.Family == "inet" && strings.HasPrefix(entry.Table.Name, "lindm_q_") {
			result[entry.Table.Name] = true
		}
	}
	return result, nil
}

// quarantineSetKey accepts the fixed numgen key in both native JSON forms:
// nft 1.0 prints a typeof set's key as its datatype ("integer"); nft 1.1 and
// later (Fedora 44) print the typeof expression itself. Anything else is not
// the action-owned set.
func quarantineSetKey(raw json.RawMessage) bool {
	var datatype string
	if json.Unmarshal(raw, &datatype) == nil {
		return datatype == "integer"
	}
	var key struct {
		Typeof struct {
			Numgen struct {
				Mode   string `json:"mode"`
				Mod    uint32 `json:"mod"`
				Offset uint32 `json:"offset"`
			} `json:"numgen"`
		} `json:"typeof"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&key) != nil {
		return false
	}
	numgen := key.Typeof.Numgen
	return numgen.Mode == "inc" && numgen.Mod == 1 && numgen.Offset == 0
}

func (p *Provider) quarantineActive(ctx context.Context, table string) (bool, []byte, error) {
	out, err := p.run(ctx, nativeRequest{command: nft, args: []string{"--json", "list", "table", "inet", table}})
	if err != nil {
		return false, nil, err
	}
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &document); err != nil {
		return false, nil, err
	}
	active, chains, drops := false, 0, 0
	for _, entry := range document.NFTables {
		if raw, exists := entry["set"]; exists {
			var set struct {
				Name     string            `json:"name"`
				Type     json.RawMessage   `json:"type"`
				Flags    []string          `json:"flags"`
				Elements []json.RawMessage `json:"elem"`
			}
			if err := json.Unmarshal(raw, &set); err != nil {
				return false, nil, err
			}
			if set.Name != "active" || !quarantineSetKey(set.Type) || !slices.Contains(set.Flags, "timeout") {
				return false, nil, ErrConflict
			}
			active = len(set.Elements) == 1
		}
		if raw, exists := entry["chain"]; exists {
			var chain struct {
				Hook   string `json:"hook"`
				Policy string `json:"policy"`
			}
			if err := json.Unmarshal(raw, &chain); err != nil {
				return false, nil, err
			}
			if slices.Contains([]string{"input", "output", "forward"}, chain.Hook) && chain.Policy == "accept" {
				chains++
			}
		}
		if raw, exists := entry["rule"]; exists {
			var rule struct {
				Expr []map[string]json.RawMessage `json:"expr"`
			}
			if err := json.Unmarshal(raw, &rule); err != nil {
				return false, nil, err
			}
			for _, expr := range rule.Expr {
				if _, ok := expr["drop"]; ok {
					drops++
				}
			}
		}
	}
	if chains != 3 || drops != 3 {
		return false, nil, ErrConflict
	}
	hash := sha256.Sum256(out)
	return active, hash[:], nil
}

func (p *Provider) removeQuarantine(ctx context.Context, table string) error {
	_, err := p.run(ctx, nativeRequest{command: nft, args: []string{"delete", "table", "inet", table}})
	return err
}

func (p *Provider) applyQuarantine(ctx context.Context, plan *agentv1.DeviceActionPlan, gate func(context.Context) error) error {
	table, err := quarantineTable(plan.GetActionId())
	if err != nil {
		return err
	}
	tables, err := p.quarantineTables(ctx)
	if err != nil {
		return err
	}
	var expired []string
	for name := range tables {
		active, _, err := p.quarantineActive(ctx, name)
		if err != nil || active {
			return fmt.Errorf("%w: existing_quarantine", ErrConflict)
		}
		expected, err := quarantineTable(strings.TrimPrefix(name, "lindm_q_"))
		if err != nil || expected != name {
			return ErrConflict
		}
		expired = append(expired, name)
	}
	if tables[table] {
		return fmt.Errorf("%w: quarantine_replay", ErrConflict)
	}
	rules, err := quarantineRules(table, plan.GetSpec().GetQuarantine().GetManagementEndpoints(), p.config.GetDnsServers(), p.config.GetQuarantineSeconds())
	if err != nil {
		return err
	}
	// Reap only previously verified expired action-owned tables in the same
	// atomic, gated transaction; kernel timeout itself needs no live process.
	slices.Sort(expired)
	var cleanup strings.Builder
	for _, name := range expired {
		fmt.Fprintf(&cleanup, "delete table inet %s\n", name)
	}
	rules = append([]byte(cleanup.String()), rules...)
	if _, err := p.run(ctx, nativeRequest{command: nft, args: []string{"--check", "--file", "-"}, input: rules}); err != nil {
		return err
	}
	if err := gate(ctx); err != nil {
		return err
	}
	if _, err := p.run(ctx, nativeRequest{command: nft, args: []string{"--file", "-"}, input: rules}); err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	checkpoint, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	active, _, err := p.quarantineActive(checkpoint, table)
	if err == nil && !active {
		err = ErrOutcomeUnknown
	}
	if err != nil {
		rollback, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return errors.Join(ErrOutcomeUnknown, err, p.removeQuarantine(rollback, table))
	}
	return nil
}

func sessionLockEvidence() string {
	return "logind D-Bus LockSessions requested; all remaining graphical sessions acknowledge LockedHint. This is not boot lock or physical desktop visibility proof."
}

// sessionLockUnreportedEvidence is the visible result when logind accepted the
// lock request but a graphical session never reported LockedHint. logind only
// relays the request; the desktop's own locker must engage and report. Lockers
// that never call SetLockedHint (for example cinnamon-screensaver on Cinnamon
// 6.6, cosmic-greeter, or a Hyprland session without a logind Lock listener)
// leave lindm unable to tell a locked screen from an unlocked one.
func sessionLockUnreportedEvidence(window time.Duration) string {
	return "session_lock_state_unreported: logind D-Bus LockSessions was accepted, but at least one graphical session did not report LockedHint within " + window.String() + ". The desktop's locker may or may not have engaged; this desktop does not report lock state to logind, so lindm cannot verify the session lock."
}

func quarantineEvidence(seconds uint32) string {
	return "Native nft quarantine observed; kernel active-set automatic rollback after " + strconv.FormatUint(uint64(seconds), 10) + " seconds. Management reachability requires successful transport delivery; delivery loss remains unknown."
}

// sessionLockAcknowledgement bounds how long a desktop may take to report
// LockedHint after logind relays LockSessions.
const sessionLockAcknowledgement = 5 * time.Second

// errSessionLockUnreported reports that the acknowledgement window elapsed
// with the executor still running: a definite observation, not an interruption.
var errSessionLockUnreported = errors.New("session_lock_state_unreported")

func (p *Provider) lockWindow() time.Duration {
	if p.lockWait > 0 {
		return p.lockWait
	}
	return sessionLockAcknowledgement
}

// logind dispatches the lock request asynchronously to each graphical session.
// Observe its acknowledgement with a deadline; never repeat the lock effect.
// When the window elapses, the last observation is returned with
// errSessionLockUnreported; cancellation of ctx remains an unknown outcome.
func (p *Provider) awaitSessionLock(ctx context.Context, spec *agentv1.DeviceActionSpec) (*agentv1.DeviceActionObservation, error) {
	window := p.lockWindow()
	deadline := p.clock().Add(window)
	wait, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var last *agentv1.DeviceActionObservation
	for {
		select {
		case <-wait.Done():
			if ctx.Err() != nil {
				return nil, errors.Join(ErrOutcomeUnknown, ctx.Err())
			}
			if last == nil {
				return nil, errors.Join(ErrOutcomeUnknown, errSessionLockUnreported)
			}
			return last, errSessionLockUnreported
		case <-ticker.C:
			observation, err := p.observe(wait, spec)
			if err != nil {
				// A native call sees the window's deadline pass before wait's
				// timer fires: a dial past it fails with an i/o timeout that is
				// context.DeadlineExceeded (pop2404-lock-quarantine-07). That
				// is the window ending, not an interruption.
				if ctx.Err() == nil && (wait.Err() != nil || !p.clock().Before(deadline)) {
					continue
				}
				return nil, errors.Join(ErrOutcomeUnknown, err)
			}
			if observation.GetSessionsLocked() {
				return observation, nil
			}
			last = observation
		}
	}
}
