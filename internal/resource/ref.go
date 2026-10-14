// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/protodata"
)

// ValidateRef rejects noncanonical aliases even when only a dependency ref is
// available. Desired identity derivation still supplies the authoritative pair.
func ValidateRef(ref *resourcev1.ResourceRef) error {
	if ref == nil {
		return errors.New("resource: missing_ref")
	}
	if err := protodata.ValidateClosed(ref.ProtoReflect()); err != nil {
		return err
	}
	rules, err := validator()
	if err != nil {
		return err
	}
	if err := rules.Validate(ref); err != nil {
		return err
	}
	key := ref.GetCanonicalKey()
	parts := strings.Split(key, "/")
	valid := false
	var identity proto.Message
	switch ref.GetKind() {
	case resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE:
		identity = &resourcev1.SystemdServiceDesired{Unit: key, Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP:
		identity = &resourcev1.LocalGroupDesired{Name: key, Presence: resourcev1.Presence_PRESENCE_PRESENT}
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER:
		identity = &resourcev1.LocalUserDesired{Name: key, Presence: resourcev1.Presence_PRESENCE_PRESENT}
	case resourcev1.ResourceKind_RESOURCE_KIND_SUDO_RULE, resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE, resourcev1.ResourceKind_RESOURCE_KIND_NETWORK_CONNECTION:
		valid = isCanonicalUUID(key)
	case resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER, resourcev1.ResourceKind_RESOURCE_KIND_TIME_SYNC, resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY, resourcev1.ResourceKind_RESOURCE_KIND_DIRECTORY_CLIENT:
		valid = key == "system"
	case resourcev1.ResourceKind_RESOURCE_KIND_TRUST_CA:
		if len(parts) == 2 && parts[0] == "system" {
			digest, err := hex.DecodeString(parts[1])
			valid = err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == parts[1]
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_DNS:
		valid = key == "system" || (len(parts) == 2 && parts[0] == "connection" && isCanonicalUUID(parts[1]))
	case resourcev1.ResourceKind_RESOURCE_KIND_PROXY:
		valid = key == "packages" || key == "system-environment" || validDesktopKey(parts)
	case resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE:
		// `<eco>/<name>` follows the device's native architecture; the
		// three-part form pins one. An empty third part is never canonical.
		if len(parts) == 2 || (len(parts) == 3 && parts[2] != "") {
			identity = &resourcev1.PackageIdentity{Ecosystem: packageEcosystem(parts[0]), NativeName: parts[1], Architecture: strings.Join(parts[2:], "")}
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY:
		valid = len(parts) == 2 && validRepositoryEcosystem(parts[0]) && isCanonicalUUID(parts[1])
	case resourcev1.ResourceKind_RESOURCE_KIND_FLATPAK_APP:
		if len(parts) == 7 && (parts[0] == "system" || parts[0] == "person") && isCanonicalUUID(parts[1]) && isCanonicalUUID(parts[2]) && parts[3] == "app" {
			// Identity field syntax stays in protobuf rather than a second regex.
			identity = &resourcev1.FlatpakAppDesired{
				Installation: &resourcev1.InstallationBinding{Binding: &resourcev1.InstallationBinding_System{System: &resourcev1.DeviceBinding{DeviceId: parts[1], EnrollmentGeneration: parts[2]}}},
				AppId:        parts[4], Architecture: parts[5], Branch: parts[6], Presence: resourcev1.Presence_PRESENCE_PRESENT,
				Remote: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: "flatpak/" + parts[1]},
			}
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_SESSION_POLICY:
		valid = key == "system/login" || validDesktopKey(parts)
	case resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY:
		valid = key == "system/local-auth"
	case resourcev1.ResourceKind_RESOURCE_KIND_SNAP_APP:
		if len(parts) == 3 && parts[0] == "system" {
			identity = &resourcev1.SnapAppDesired{Name: parts[1], InstanceKey: parts[2], Presence: resourcev1.Presence_PRESENCE_PRESENT, Channel: "stable", Confinement: resourcev1.SnapConfinement_SNAP_CONFINEMENT_STRICT}
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_CERTIFICATE_ENROLLMENT:
		valid = len(parts) == 4 && isCanonicalUUID(parts[0]) && (parts[1] == "device" || parts[1] == "person") && isCanonicalUUID(parts[2]) && isCanonicalUUID(parts[3])
	case resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE:
		identity = &resourcev1.ManagedFileDesired{Path: key, Presence: resourcev1.Presence_PRESENCE_ABSENT}
	case resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL:
		identity = &resourcev1.SysctlDesired{Key: key, Value: "0"}
	case resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION:
		if len(parts) == 2 {
			switch parts[0] {
			case "timer":
				identity = &resourcev1.TimerDefinition{
					Unit:     parts[1],
					Service:  &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "example.service"},
					Schedule: &resourcev1.TimerSchedule{Schedule: &resourcev1.TimerSchedule_IntervalSeconds{IntervalSeconds: 1}},
				}
			case "drop-in":
				identity = &resourcev1.ServiceDropIn{Unit: parts[1], CpuWeight: proto.Uint32(100)}
			}
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE:
		valid = key == "system/root"
	}
	if identity != nil {
		valid = rules.Validate(identity) == nil
	}
	if !valid {
		return errors.New("resource: noncanonical_ref")
	}
	return nil
}

func isCanonicalUUID(value string) bool {
	canonical, err := canonicalUUID(value)
	return err == nil && value == canonical
}

func validDesktopKey(parts []string) bool {
	return len(parts) == 3 && parts[0] == "person" && isCanonicalUUID(parts[1]) && (parts[2] == "gnome" || parts[2] == "kde")
}

func validRepositoryEcosystem(value string) bool {
	switch value {
	case "apt", "rpm", "alpm", "flatpak", "nix", "ostree":
		return true
	default:
		return false
	}
}

func packageEcosystem(value string) resourcev1.PackageEcosystem {
	switch value {
	case "deb":
		return resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB
	case "rpm":
		return resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM
	case "alpm":
		return resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM
	case "nix":
		return resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_NIX
	default:
		return resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_UNSPECIFIED
	}
}

func packageSourceMatches(identity *resourcev1.PackageIdentity, source *resourcev1.ResourceRef) bool {
	var ecosystem string
	switch identity.GetEcosystem() {
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB:
		ecosystem = "apt"
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM:
		ecosystem = "rpm"
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM:
		ecosystem = "alpm"
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_NIX:
		ecosystem = "nix"
	default:
		return false
	}
	return source.GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY && strings.HasPrefix(source.GetCanonicalKey(), ecosystem+"/")
}
