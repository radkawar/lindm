// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdate

import (
	"cmp"
	"errors"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// maxLedger mirrors OSUpdateRunState.pending_since.
const maxLedger = 16384

var errLedgerCapacity = errors.New("pending_update_capacity")

type packageKey struct{ name, arch string }

func comparePackageKeys(a, b packageKey) int {
	return cmp.Or(cmp.Compare(a.name, b.name), cmp.Compare(a.arch, b.arch))
}

// pendingPackage is one package with an update pending in the native cache.
// security means the native backend classifies the candidate as a security
// fix (APT security pocket, RPM security advisory).
type pendingPackage struct {
	key      packageKey
	security bool
}

// updateLedger keeps each still-pending package's first observation and
// records newly pending packages at anchor: the window start for window runs,
// so a run's position inside its window never shifts the deferral. Packages
// without a pending update are dropped, so a later update of the same package
// restarts its deferral. The result is sorted.
func updateLedger(previous []*agentv1.OSUpdateDeferralEntry, pending []pendingPackage, anchor time.Time) ([]*agentv1.OSUpdateDeferralEntry, error) {
	if len(pending) > maxLedger {
		return nil, errLedgerCapacity
	}
	known := make(map[packageKey]*timestamppb.Timestamp, len(previous))
	for _, entry := range previous {
		known[packageKey{entry.GetName(), entry.GetArchitecture()}] = entry.GetFirstSeen()
	}
	seen := make(map[packageKey]bool, len(pending))
	ledger := make([]*agentv1.OSUpdateDeferralEntry, 0, len(pending))
	for _, p := range pending {
		if seen[p.key] {
			continue
		}
		seen[p.key] = true
		first, ok := known[p.key]
		if !ok || first == nil {
			first = timestamppb.New(anchor)
		}
		ledger = append(ledger, &agentv1.OSUpdateDeferralEntry{Name: p.key.name, Architecture: p.key.arch, FirstSeen: first})
	}
	slices.SortFunc(ledger, func(a, b *agentv1.OSUpdateDeferralEntry) int {
		return comparePackageKeys(packageKey{a.GetName(), a.GetArchitecture()}, packageKey{b.GetName(), b.GetArchitecture()})
	})
	return ledger, nil
}

// runPlan splits the selected pending packages into the ones whose deferral
// has elapsed and the ones the native run must exclude.
type runPlan struct {
	selected, eligible int
	deferred           []packageKey
}

func selectedPackage(selection resourcev1.UpdateSelection, p pendingPackage) bool {
	return selection == resourcev1.UpdateSelection_UPDATE_SELECTION_ALL || (selection == resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY && p.security)
}

// deferral is the policy's deferral rule. Days are calendar days in the
// maintenance window zone, so deferral_days equal to the window period always
// lands exactly on a later window start, across DST changes too.
type deferral struct {
	days uint32
	zone *time.Location
}

// planRun applies the deferral at the instant at (the window start for
// window runs): a selected package is eligible once first_seen plus the
// deferral's calendar days is not after at. A first observation in the
// future (clock step back) is not yet eligible. A nil rule (patch now) makes
// every selected package eligible.
func planRun(selection resourcev1.UpdateSelection, pending []pendingPackage, ledger []*agentv1.OSUpdateDeferralEntry, rule *deferral, at time.Time) runPlan {
	first := make(map[packageKey]time.Time, len(ledger))
	for _, entry := range ledger {
		first[packageKey{entry.GetName(), entry.GetArchitecture()}] = entry.GetFirstSeen().AsTime()
	}
	var plan runPlan
	seen := make(map[packageKey]bool, len(pending))
	for _, p := range pending {
		if seen[p.key] || !selectedPackage(selection, p) {
			continue
		}
		seen[p.key] = true
		plan.selected++
		since, ok := first[p.key]
		if !ok {
			since = at
		}
		if rule == nil || !since.In(rule.zone).AddDate(0, 0, int(rule.days)).After(at) {
			plan.eligible++
			continue
		}
		plan.deferred = append(plan.deferred, p.key)
	}
	slices.SortFunc(plan.deferred, comparePackageKeys)
	return plan
}
