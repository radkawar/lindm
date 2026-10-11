//go:build linux

package passwordprovider

import (
	"context"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
)

type interruptedStore struct {
	ledger    *agentv1.ResourceOwnershipLedger
	mutations int
}

func (s *interruptedStore) LoadResourceOwnership(context.Context, string, string, string, *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error) {
	if s.ledger == nil {
		return nil, journal.ErrResourceOwnershipNotFound
	}
	return proto.CloneOf(s.ledger), nil
}
func (s *interruptedStore) ClaimResourceOwnership(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error) {
	s.mutations++
	return nil, errors.New("unexpected claim")
}
func (s *interruptedStore) BeginResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot, []agentv1.ResourceOwnedDimension) (*agentv1.ResourceOwnershipLedger, error) {
	s.mutations++
	return nil, errors.New("unexpected effect")
}
func (s *interruptedStore) CompleteResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error) {
	s.mutations++
	return nil, errors.New("unexpected completion")
}
func TestInterruptedPolicyRefusesObservationAndReplay(t *testing.T) {
	store := &interruptedStore{ledger: &agentv1.ResourceOwnershipLedger{State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN}}
	reads := 0
	p := &Provider{store: store, observe: func(context.Context, *resourcev1.PasswordPolicyDesired) (*agentv1.ResourceOwnershipSnapshot, error) {
		reads++
		return nil, errors.New("unexpected native read")
	}}
	desired := &resourcev1.ResourceDesiredState{Ref: passwordRef(), State: &resourcev1.ResourceDesiredState_PasswordPolicy{PasswordPolicy: &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14)}}}
	for _, op := range []resourcev1.ResourceOperation{resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE} {
		if _, err := p.Plan(context.Background(), desired, op); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("interrupted policy result: %v", err)
		}
	}
	if reads != 0 || store.mutations != 0 {
		t.Fatalf("uncertain action was replayed: reads=%d writes=%d", reads, store.mutations)
	}
}
func TestMissingModuleReturnsTypedPackageWithoutMutation(t *testing.T) {
	store := &interruptedStore{}
	missing := missingModule(&resourcev1.PlatformProduct{OsId: "ubuntu"}, 1, errors.New("missing ELF module"))
	p := &Provider{store: store, config: Config{Ownership: &agentv1.ResourceOwnershipBinding{Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION, AdoptionApprovalId: proto.String("d3742200-85f7-4a40-8bc0-87e646c05fe6")}}}, observe: func(context.Context, *resourcev1.PasswordPolicyDesired) (*agentv1.ResourceOwnershipSnapshot, error) {
		return nil, missing
	}}
	desired := &resourcev1.ResourceDesiredState{Ref: passwordRef(), State: &resourcev1.ResourceDesiredState_PasswordPolicy{PasswordPolicy: &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(14)}}}
	_, err := p.Plan(context.Background(), desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	var prerequisite *PrerequisiteError
	if !errors.As(err, &prerequisite) || !errors.Is(err, ErrMissingModule) || prerequisite.Package.GetNativeName() != "libpam-pwquality" || prerequisite.Package.GetEcosystem() != resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
		t.Fatalf("missing typed package prerequisite: %v", err)
	}
	if store.mutations != 0 {
		t.Fatal("missing package caused ownership/native mutation")
	}
}
func TestRefusesCrossDistroManagerGuessing(t *testing.T) {
	for _, platform := range []*resourcev1.PlatformProduct{{OsId: "debian", Version: "13"}, {OsId: "ubuntu", Version: "22.04"}, {OsId: "fedora", Version: "43"}, {OsId: "rhel", Version: "10.1"}, {OsId: "almalinux", Version: "9.7"}, {OsId: "rocky", Version: "9.8"}} {
		if productSupported(platform) {
			t.Fatalf("unqualified native manager guessed: %v", platform)
		}
	}
	for _, platform := range []*resourcev1.PlatformProduct{{OsId: "ubuntu", Version: "24.04"}, {OsId: "fedora", Version: "44"}, {OsId: "rhel", Version: "9.8"}, {OsId: "almalinux", Version: "9.8"}, {OsId: "rhel", Version: "10.2"}, {OsId: "almalinux", Version: "10.2"}} {
		if !productSupported(platform) {
			t.Fatal(platform)
		}
	}
}
func TestAuthselectFeaturePrerequisiteIsReadOnly(t *testing.T) {
	before := policyFixture()
	before.PasswordPolicy.ManagerProfile = "sssd"
	before.PasswordPolicy.EnabledFeatures = []agentv1.PasswordNativeFeature{1}
	target := proto.CloneOf(before)
	target.PasswordPolicy.EnabledFeatures = append(target.PasswordPolicy.EnabledFeatures, 2)
	calls := 0
	run := func(_ context.Context, path string, args ...string) ([]byte, error) {
		calls++
		if path != "/usr/bin/authselect" || len(args) != 2 || args[0] != "list-features" || args[1] != "sssd" {
			t.Fatal("preflight changed manager")
		}
		return []byte("with-faillock\n"), nil
	}
	if err := managerChangeSupported(context.Background(), &resourcev1.PlatformProduct{OsId: "fedora"}, before, target, run); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}

func TestAuthselectFeatureCannotChangeIdentityOrDesktopPolicy(t *testing.T) {
	before := policyFixture()
	before.PasswordPolicy.ManagerProfile = "sssd"
	before.PasswordPolicy.EnabledFeatures = []agentv1.PasswordNativeFeature{1}
	target := proto.CloneOf(before)
	target.PasswordPolicy.EnabledFeatures = append(target.PasswordPolicy.EnabledFeatures, 2)
	for _, drift := range []bool{false, true} {
		calls := 0
		run := func(_ context.Context, path string, args ...string) ([]byte, error) {
			calls++
			if path != "/usr/bin/authselect" || len(args) == 0 {
				t.Fatal("unexpected executable")
			}
			switch args[0] {
			case "list-features":
				return []byte("with-pwhistory\nwith-faillock\nwith-sudo\n"), nil
			case "current":
				if !slices.Equal(args, []string{"current", "--raw"}) {
					t.Fatal(args)
				}
				return []byte("sssd with-sudo\n"), nil
			case "test":
				if len(args) < 6 || !slices.Equal(args[:5], []string{"test", "sssd", "--nsswitch", "--dconf-db", "--dconf-lock"}) || !slices.Contains(args, "with-sudo") {
					t.Fatal("unrelated feature lost or rendering changed")
				}
				if drift && slices.Contains(args, "with-pwhistory") {
					return []byte("passwd: files ldap\n"), nil
				}
				return []byte("passwd: files sss\n"), nil
			default:
				t.Fatalf("preflight attempted native effect %v", args)
				return nil, ErrUnsupported
			}
		}
		err := managerChangeSupported(context.Background(), &resourcev1.PlatformProduct{OsId: "fedora", Version: "44"}, before, target, run)
		if (drift && !errors.Is(err, ErrUnsupported)) || (!drift && err != nil) || calls != 4 {
			t.Fatalf("non-PAM drift=%t calls=%d err=%v", drift, calls, err)
		}
	}
}

func TestAuthselectSelectionRejectsOptionAndPathInjection(t *testing.T) {
	for _, raw := range []string{"", "--help", "custom/../sssd", "sssd --force", "sssd with-faillock with-faillock", "sssd with/other"} {
		if _, err := authselectSelection([]byte(raw)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsafe native selection %q accepted: %v", raw, err)
		}
	}
	if got, err := authselectSelection([]byte("custom/lindm-local with-pwhistory with-sudo\n")); err != nil || len(got) != 3 {
		t.Fatalf("valid native selection rejected: %v %v", got, err)
	}
}
