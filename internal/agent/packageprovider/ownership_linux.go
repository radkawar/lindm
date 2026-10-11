//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"lindm/internal/custody"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
)

func (p *Provider) installedIdentity(ctx context.Context, record *resourcev1.NativePackageRecord) ([]byte, error) {
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.package.installed-identity.v1\x00"))
	_, _ = h.Write(record.GetNativeIdentitySha256())
	identity := record.GetPackage()
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM {
		result, err := p.run(ctx, "/usr/bin/rpm", []string{"--query", "--queryformat", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\t%{INSTALLTID}\t%{SHA256HEADER}\n", identity.GetNativeName() + "." + identity.GetArchitecture()}, "/", nil)
		if err != nil {
			return nil, err
		}
		if len(result.stderr) != 0 {
			return nil, errors.New("packageprovider: RPM identity probe warned")
		}
		row := strings.TrimSuffix(string(result.stdout), "\n")
		fields := strings.Split(row, "\t")
		if len(fields) != 8 || strings.Contains(row, "\n") || fields[0] != identity.GetNativeName() || fields[4] != identity.GetArchitecture() || fields[7] == "(none)" {
			return nil, errors.New("packageprovider: incomplete RPM installed identity")
		}
		_, _ = h.Write(result.stdout)
		return h.Sum(nil), nil
	}
	base := ""
	for _, candidate := range []string{identity.GetNativeName() + ":" + identity.GetArchitecture(), identity.GetNativeName()} {
		path := filepath.Join("/var/lib/dpkg/info", candidate+".list")
		if _, err := os.Lstat(path); err == nil {
			if base != "" {
				return nil, errors.New("packageprovider: ambiguous dpkg control identity")
			}
			base = filepath.Join("/var/lib/dpkg/info", candidate)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if base == "" {
		return nil, errors.New("packageprovider: installed dpkg control record missing")
	}
	for _, suffix := range []string{".list", ".md5sums", ".conffiles"} {
		path := base + suffix
		data, err := custody.ReadRoot(path, maxOutput, false)
		if errors.Is(err, os.ErrNotExist) && suffix != ".list" {
			continue
		}
		if err != nil {
			return nil, err
		}
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			return nil, err
		}
		digest := sha256.Sum256(data)
		_, _ = fmt.Fprintf(h, "%s:%d:%d:%d:%d:%d:", suffix, stat.Dev, stat.Ino, stat.Size, stat.Ctim.Sec, stat.Ctim.Nsec)
		_, _ = h.Write(digest[:])
	}
	return h.Sum(nil), nil
}

func releaseTarget(desired *resourcev1.ResourceDesiredState, before *resourcev1.ResourceObservation, ledger *agentv1.ResourceOwnershipLedger) (*resourcev1.NativePackageDesired, []byte, *resourcev1.OwnershipInverseBinding, error) {
	if ledger == nil || ledger.GetLastApplied() == nil || ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, nil, nil, ErrOutcomeUnknown
	}
	current := before.GetNativePackage()
	last := ledger.GetLastApplied().GetObservation().GetNativePackage()
	if !releaseDimensionsMatch(current, last, ledger.GetOwnedDimensions()) {
		return nil, nil, nil, fmt.Errorf("%w: release conflicts with external package/pin changes", ErrConflict)
	}
	effective := proto.CloneOf(desired.GetNativePackage())
	baseline := ledger.GetBaseline().GetObservation().GetNativePackage()
	pin := bytes.Clone(current.GetPinContents())
	target := current
	if ledger.GetOwner().GetPolicy().GetRelease() == resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED {
		pin = bytes.Clone(baseline.GetPinContents())
		if effective.GetRemoval() != resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_RETAIN_INSTALLATION {
			target = baseline
		}
	}
	if target.GetInstalled() {
		effective.Presence = resourcev1.Presence_PRESENCE_PRESENT
		effective.Version = &resourcev1.NativePackageDesired_Exact{Exact: proto.CloneOf(target.GetRecord().GetVersion())}
		if !target.GetRecord().GetProvenanceKnown() {
			return nil, nil, nil, errors.New("packageprovider: release target provenance unknown")
		}
		effective.Repository = proto.CloneOf(target.GetRecord().GetSource())
	} else {
		effective.Presence = resourcev1.Presence_PRESENCE_ABSENT
		effective.Version = &resourcev1.NativePackageDesired_Any{Any: &resourcev1.AnyApprovedVersion{}}
	}
	if err := checkNoDowngrade(current.GetRecord().GetVersion(), effective.GetExact()); err != nil {
		return nil, nil, nil, err
	}
	ledgerDigest, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, nil, nil, err
	}
	lastDigest, err := digestMessage(ledger.GetLastApplied())
	if err != nil {
		return nil, nil, nil, err
	}
	nativeDigest, err := digestMessage(current)
	if err != nil {
		return nil, nil, nil, err
	}
	inverseBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(effective)
	if err != nil {
		return nil, nil, nil, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.package.release.v1\x00"))
	_, _ = fmt.Fprintf(h, "%d:", len(inverseBytes))
	_, _ = h.Write(inverseBytes)
	_, _ = h.Write(pin)
	return effective, pin, &resourcev1.OwnershipInverseBinding{LedgerRevisionSha256: ledgerDigest[:], LastAppliedSha256: lastDigest, NativeIdentitySha256: nativeDigest, InverseSha256: h.Sum(nil)}, nil
}
func releaseDimensionsMatch(current, last *resourcev1.NativePackageObservation, dimensions []agentv1.ResourceOwnedDimension) bool {
	if current == nil || last == nil {
		return false
	}
	for _, dimension := range dimensions {
		switch dimension {
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PRESENCE:
			if current.GetInstalled() != last.GetInstalled() {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_VERSION:
			if !samePackageRecord(current.GetRecord(), last.GetRecord()) || !bytes.Equal(current.GetRecord().GetNativeIdentitySha256(), last.GetRecord().GetNativeIdentitySha256()) {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PIN:
			if !proto.Equal(current.GetPinFile(), last.GetPinFile()) || !bytes.Equal(current.GetPinContents(), last.GetPinContents()) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func packageDimensions(plan *resourcev1.ResourcePlan, ledger *agentv1.ResourceOwnershipLedger) []agentv1.ResourceOwnedDimension {
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return append([]agentv1.ResourceOwnedDimension(nil), ledger.GetOwnedDimensions()...)
	}
	dimensions := []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PRESENCE}
	if plan.GetNativePackage().GetDesired().GetExact() != nil {
		dimensions = append(dimensions, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_VERSION)
	}
	if plan.GetNativePackage().GetChangePin() {
		dimensions = append(dimensions, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PIN)
	}
	return dimensions
}
