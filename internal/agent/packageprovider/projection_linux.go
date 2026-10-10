//go:build linux

package packageprovider

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/dnf"
)

// ValidateStagingProjection checks the actual host pin before the parent starts
// the PREPARE-only read-only bind. The helper sees projected candidate bytes;
// only this outside-the-namespace check can prove the original host identity.
func ValidateStagingProjection(request *agentv1.NativePackageTransactionRequest) error {
	if request == nil {
		return ErrConflict
	}
	if request.GetOriginalPin() == nil {
		if request.CandidatePinContents != nil || request.CandidatePinSha256 != nil {
			return ErrConflict
		}
		return nil
	}
	if request.GetOperation() != agentv1.NativePackageHelperOperation_NATIVE_PACKAGE_HELPER_OPERATION_PREPARE || request.GetDesired().GetNativePackage().GetPackage().GetEcosystem() != resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM || request.GetOriginalPin().GetPath() != "/etc/dnf/versionlock.toml" {
		return ErrConflict
	}
	identity, _, err := readPin("/etc/dnf/versionlock.toml")
	if err != nil {
		return err
	}
	if identity == nil || !proto.Equal(identity, request.GetOriginalPin()) {
		return errors.New("packageprovider: original versionlock changed before projection")
	}
	digest := sha256.Sum256(request.GetCandidatePinContents())
	if !bytes.Equal(digest[:], request.GetCandidatePinSha256()) {
		return ErrConflict
	}
	_, err = dnf.ParseVersionlock(request.GetCandidatePinContents())
	return err
}
