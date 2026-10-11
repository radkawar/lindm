//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/accountprovider"
	"lindm/internal/agent/definitionprovider"
	"lindm/internal/agent/encryptionprovider"
	"lindm/internal/agent/fileprovider"
	"lindm/internal/agent/firewallprovider"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/osupdateprovider"
	"lindm/internal/agent/packageprovider"
	"lindm/internal/agent/passwordprovider"
	"lindm/internal/agent/serviceprovider"
	"lindm/internal/agent/sysctlprovider"
)

func TestAdmissionRefusalClassifiesOnlyBoundedProviderCauses(t *testing.T) {
	for _, group := range []struct {
		reason  agentv1.ResourceAdmissionRefusalReason
		failure agentv1.ResourceExecutionFailure
		causes  []error
	}{
		{agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_BASELINE_UNKNOWN, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED,
			[]error{serviceprovider.ErrBaselineUnknown, definitionprovider.ErrBaselineUnknown}},
		{agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED,
			[]error{serviceprovider.ErrUnsupported, accountprovider.ErrUnsupported, definitionprovider.ErrUnsupported, encryptionprovider.ErrUnsupported, fileprovider.ErrUnsupported, firewallprovider.ErrUnsupported, packageprovider.ErrUnsupported, passwordprovider.ErrUnsupported, sysctlprovider.ErrUnsupported, osupdateprovider.ErrUnsupported,
				// A foreign POSIX ACL observed through the shared native file
				// boundary was retried forever as an internal error.
				fmt.Errorf("%w: cannot preserve security xattr %q", nativefile.ErrUnsupported, "system.posix_acl_access")}},
		{agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION,
			[]error{serviceprovider.ErrConflict, accountprovider.ErrConflict, accountprovider.ErrUnsafe, definitionprovider.ErrConflict, definitionprovider.ErrProtected, encryptionprovider.ErrConflict, fileprovider.ErrConflict, fileprovider.ErrUnsafePath, nativefile.ErrConflict, nativefile.ErrUnsafePath, firewallprovider.ErrConflict, packageprovider.ErrConflict, passwordprovider.ErrConflict, passwordprovider.ErrAccessGuard, passwordprovider.ErrMissingModule, sysctlprovider.ErrConflict, journal.ErrResourceOwnershipConflict, journal.ErrResourceOwnershipDrift,
				osupdateprovider.ErrConflict, osupdateprovider.ErrMissingPrerequisite,
				// A missing native automatic-update tool is a typed precondition
				// naming its package, never an unsupported platform.
				&osupdateprovider.PrerequisiteError{Package: &resourcev1.PackageIdentity{NativeName: "unattended-upgrades"}, Cause: errors.New("not installed")}}},
	} {
		for _, cause := range group.causes {
			reason, failure, ok := resourceAdmissionCause(fmt.Errorf("bounded native preflight: %w", cause))
			if !ok || reason != group.reason || failure != group.failure {
				t.Fatalf("incorrect classification for %v: %v %v %v", cause, reason, failure, ok)
			}
		}
	}
}

func TestAdmissionRefusalCannotHideAuthorityCustodyOrUncertainEffects(t *testing.T) {
	for _, cause := range []error{
		context.Canceled, context.DeadlineExceeded, errResourceRejected, errResourceExpired, errIdentityExpired,
		errSessionPending, errSessionRequired, errRenewalPending, errExecutionTrustRejected, errRecoveryHold, errInternal,
		errClosed, errInvalid, journal.ErrRecoveryHold, journal.ErrResourceOwnershipUnknown, journal.ErrResourceOwnershipCapacity, journal.ErrClosed,
		serviceprovider.ErrOutcomeUnknown, accountprovider.ErrOutcomeUnknown, definitionprovider.ErrOutcomeUnknown,
		fileprovider.ErrOutcomeUnknown, firewallprovider.ErrOutcomeUnknown, packageprovider.ErrOutcomeUnknown, passwordprovider.ErrOutcomeUnknown, sysctlprovider.ErrOutcomeUnknown, osupdateprovider.ErrOutcomeUnknown,
	} {
		if _, _, ok := resourceAdmissionCause(errors.Join(serviceprovider.ErrUnsupported, cause)); ok {
			t.Fatalf("unsafe error was converted to refusal: %v", cause)
		}
	}
	if _, _, ok := resourceAdmissionCause(errors.New("unclassified native failure")); ok {
		t.Fatal("unclassified error became authenticated native diagnosis")
	}
}
