// Package resource owns the closed resource vocabulary, canonical identity and
// cross-kind semantic claims. It does not select or execute native providers,
// grant authority, acquire ownership, or claim platform qualification.
package resource

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/protodata"
)

// Serialized envelope bounds are distinct from per-field protobuf validation.
const (
	MaxDesiredBytes      = 64 << 10
	MaxObservationBytes  = 64 << 10
	MaxVerificationBytes = 64 << 10
	MaxPlanBytes         = 256 << 10
)

var validator = sync.OnceValues(func() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(
		&resourcev1.ResourceDesiredState{}, &resourcev1.ResourceObservation{},
		&resourcev1.ResourcePlan{}, &resourcev1.ResourceVerification{},
		&resourcev1.ResourceClaim{},
		&resourcev1.PackageTransactionManifest{}, &resourcev1.AppTransactionManifest{},
		&resourcev1.DeploymentTransactionManifest{},
	))
})

// Initialize compiles all resource CEL constraints before serving requests.
func Initialize() error {
	_, err := validator()
	return err
}

// Capability is derived from the trusted, closed kind registry, never from an
// untrusted requested capability string. Unspecified and future numbers fail.
func Capability(kind resourcev1.ResourceKind) (string, error) {
	switch kind {
	case resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE:
		return "systemd.service.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP:
		return "local.group.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER:
		return "local.user.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_SUDO_RULE:
		return "sudo.rule.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER:
		return "ssh.server.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_TIME_SYNC:
		return "time.sync.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_TRUST_CA:
		return "trust.ca.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE:
		return "firewall.zone.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_NETWORK_CONNECTION:
		return "network.connection.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_DNS:
		return "network.dns.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_PROXY:
		return "network.proxy.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE:
		return "package.native.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY:
		return "package.repository.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_FLATPAK_APP:
		return "flatpak.app.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY:
		return "os.update.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_SESSION_POLICY:
		return "session.policy.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY:
		return "password.policy.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_SNAP_APP:
		return "snap.app.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_CERTIFICATE_ENROLLMENT:
		return "certificate.enrollment.v1", nil
	case resourcev1.ResourceKind_RESOURCE_KIND_DIRECTORY_CLIENT:
		return "directory.client.v1", nil
	default:
		return "", errors.New("resource: unknown_kind")
	}
}

// CanonicalRef derives identity from the selected desired arm. A missing ref is
// allowed here so publishers can construct it; a supplied ref is not consulted.
// ValidateDesired additionally requires the supplied pair to match exactly.
func CanonicalRef(desired *resourcev1.ResourceDesiredState) (*resourcev1.ResourceRef, error) {
	if desired == nil {
		return nil, errors.New("resource: missing_desired")
	}
	if proto.Size(desired) > MaxDesiredBytes {
		return nil, errors.New("resource: desired_too_large")
	}
	if err := protodata.ValidateClosed(desired.ProtoReflect()); err != nil {
		return nil, fmt.Errorf("validate closed resource: %w", err)
	}
	message := desired.ProtoReflect()
	arm := message.WhichOneof(message.Descriptor().Oneofs().ByName("state"))
	if arm == nil || !message.Get(arm).Message().IsValid() {
		return nil, errors.New("resource: missing_desired_arm")
	}
	rules, err := validator()
	if err != nil {
		return nil, fmt.Errorf("compile resource validation: %w", err)
	}
	if err := rules.Validate(message.Get(arm).Message().Interface()); err != nil {
		return nil, fmt.Errorf("validate resource arm: %w", err)
	}
	if err := validateCanonicalScalars(message.Get(arm).Message()); err != nil {
		return nil, err
	}
	kind := resourcev1.ResourceKind(arm.Number() - 9)
	if _, err := Capability(kind); err != nil {
		return nil, err
	}
	var key string
	switch state := desired.GetState().(type) {
	case *resourcev1.ResourceDesiredState_SystemdService:
		key = state.SystemdService.GetUnit()
	case *resourcev1.ResourceDesiredState_LocalGroup:
		key = state.LocalGroup.GetName()
	case *resourcev1.ResourceDesiredState_LocalUser:
		key = state.LocalUser.GetName()
	case *resourcev1.ResourceDesiredState_SudoRule:
		key, err = canonicalUUID(state.SudoRule.GetRuleId())
	case *resourcev1.ResourceDesiredState_SshServer, *resourcev1.ResourceDesiredState_TimeSync,
		*resourcev1.ResourceDesiredState_OsUpdate, *resourcev1.ResourceDesiredState_DirectoryClient:
		key = "system"
	case *resourcev1.ResourceDesiredState_TrustCa:
		certificate, parseErr := x509.ParseCertificate(state.TrustCa.GetCertificateDer())
		if parseErr != nil {
			return nil, fmt.Errorf("parse CA certificate: %w", parseErr)
		}
		if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("resource: invalid_ca_constraints")
		}
		if bytes.Equal(certificate.RawIssuer, certificate.RawSubject) {
			if err := certificate.CheckSignatureFrom(certificate); err != nil {
				return nil, fmt.Errorf("verify self-signed CA certificate: %w", err)
			}
		}
		digest := sha256.Sum256(certificate.Raw)
		key = "system/" + hex.EncodeToString(digest[:])
	case *resourcev1.ResourceDesiredState_FirewallZone:
		key, err = canonicalUUID(state.FirewallZone.GetZoneId())
	case *resourcev1.ResourceDesiredState_NetworkConnection:
		key, err = canonicalUUID(state.NetworkConnection.GetConnectionUuid())
	case *resourcev1.ResourceDesiredState_Dns:
		key = "system"
		if connection := state.Dns.GetConnection(); connection != nil {
			key, err = canonicalUUID(connection.GetConnectionUuid())
			key = "connection/" + key
		}
	case *resourcev1.ResourceDesiredState_Proxy:
		switch scope := state.Proxy.GetScope().GetConsumer().(type) {
		case *resourcev1.ProxyConsumer_Packages:
			key = "packages"
		case *resourcev1.ProxyConsumer_SystemEnvironment:
			key = "system-environment"
		case *resourcev1.ProxyConsumer_Person:
			key, err = desktopKey(scope.Person)
		}
	case *resourcev1.ResourceDesiredState_NativePackage:
		key = packageKey(state.NativePackage.GetPackage())
	case *resourcev1.ResourceDesiredState_Repository:
		key, err = canonicalUUID(state.Repository.GetRepositoryId())
		key = repositoryEcosystem(state.Repository) + "/" + key
	case *resourcev1.ResourceDesiredState_FlatpakApp:
		key, err = installationKey(state.FlatpakApp.GetInstallation())
		key += "/app/" + state.FlatpakApp.GetAppId() + "/" + state.FlatpakApp.GetArchitecture() + "/" + state.FlatpakApp.GetBranch()
	case *resourcev1.ResourceDesiredState_SessionPolicy:
		key = "system/login"
		if person := state.SessionPolicy.GetScope().GetPersonDesktop(); person != nil {
			key, err = desktopKey(person)
		}
	case *resourcev1.ResourceDesiredState_PasswordPolicy:
		key = "system/local-auth"
	case *resourcev1.ResourceDesiredState_SnapApp:
		key = "system/" + state.SnapApp.GetName() + "/" + state.SnapApp.GetInstanceKey()
	case *resourcev1.ResourceDesiredState_CertificateEnrollment:
		key, err = canonicalUUID(state.CertificateEnrollment.GetCredentialId())
		if err == nil {
			var binding string
			binding, err = subjectKey(state.CertificateEnrollment.GetSubject())
			key += "/" + binding
		}
	default:
		return nil, errors.New("resource: unknown_desired_arm")
	}
	if err != nil {
		return nil, err
	}
	ref := &resourcev1.ResourceRef{Kind: kind, CanonicalKey: key}
	if err := rules.Validate(ref); err != nil {
		return nil, fmt.Errorf("validate canonical resource ref: %w", err)
	}
	return ref, nil
}

// ValidateDesired checks closed shape, serialized bounds and canonical identity.
func ValidateDesired(desired *resourcev1.ResourceDesiredState) error {
	ref, err := CanonicalRef(desired)
	if err != nil {
		return err
	}
	rules, err := validator()
	if err != nil {
		return err
	}
	if err := rules.Validate(desired); err != nil {
		return fmt.Errorf("validate resource desired: %w", err)
	}
	if !proto.Equal(ref, desired.GetRef()) {
		return errors.New("resource: ref_mismatch")
	}
	return nil
}

func canonicalUUID(value string) (string, error) {
	id, err := uuid.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse resource UUID: %w", err)
	}
	return id.String(), nil
}

func packageKey(identity *resourcev1.PackageIdentity) string {
	var ecosystem string
	switch identity.GetEcosystem() {
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB:
		ecosystem = "deb"
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM:
		ecosystem = "rpm"
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM:
		ecosystem = "alpm"
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_NIX:
		ecosystem = "nix"
	}
	return ecosystem + "/" + identity.GetNativeName() + "/" + identity.GetArchitecture()
}

func repositoryEcosystem(repository *resourcev1.RepositoryDesired) string {
	switch repository.GetSource().(type) {
	case *resourcev1.RepositoryDesired_Apt:
		return "apt"
	case *resourcev1.RepositoryDesired_Rpm:
		return "rpm"
	case *resourcev1.RepositoryDesired_Alpm:
		return "alpm"
	case *resourcev1.RepositoryDesired_Flatpak:
		return "flatpak"
	case *resourcev1.RepositoryDesired_Nix:
		return "nix"
	case *resourcev1.RepositoryDesired_Ostree:
		return "ostree"
	default:
		return ""
	}
}

func deviceKey(binding *resourcev1.DeviceBinding) (string, error) {
	device, err := canonicalUUID(binding.GetDeviceId())
	if err != nil {
		return "", err
	}
	generation, err := canonicalUUID(binding.GetEnrollmentGeneration())
	return device + "/" + generation, err
}

func personKey(binding *resourcev1.PersonBinding) (string, error) {
	assignment, err := canonicalUUID(binding.GetAssignmentId())
	if err != nil {
		return "", err
	}
	generation, err := canonicalUUID(binding.GetAccount().GetUidGeneration())
	return assignment + "/" + generation, err
}

func desktopKey(binding *resourcev1.PersonDesktopBinding) (string, error) {
	assignment, err := canonicalUUID(binding.GetPerson().GetAssignmentId())
	if err != nil {
		return "", err
	}
	desktop := "gnome"
	if binding.GetDesktop() == resourcev1.Desktop_DESKTOP_KDE {
		desktop = "kde"
	}
	return "person/" + assignment + "/" + desktop, nil
}

func installationKey(binding *resourcev1.InstallationBinding) (string, error) {
	if binding.GetSystem() != nil {
		key, err := deviceKey(binding.GetSystem())
		return "system/" + key, err
	}
	key, err := personKey(binding.GetPerson())
	return "person/" + key, err
}

func subjectKey(binding *resourcev1.CredentialSubjectBinding) (string, error) {
	if binding.GetDevice() != nil {
		key, err := deviceKey(binding.GetDevice())
		return "device/" + key, err
	}
	key, err := personKey(binding.GetPerson())
	return "person/" + key, err
}

// RefDigest is domain separated and length delimits both kind and key; it does
// not hash an ambiguous concatenation of their printable forms.
func RefDigest(ref *resourcev1.ResourceRef) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if err := ValidateRef(ref); err != nil {
		return result, err
	}
	h := sha256.New()
	writeHashField(h, []byte("lindm.resource-ref.v1"))
	var kind [4]byte
	binary.BigEndian.PutUint32(kind[:], uint32(ref.GetKind()))
	writeHashField(h, kind[:])
	writeHashField(h, []byte(ref.GetCanonicalKey()))
	copy(result[:], h.Sum(nil))
	return result, nil
}

func writeHashField(h hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	// hash.Hash.Write is specified never to return an error.
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}

// DesiredDigest binds exact canonical typed desired bytes to a versioned domain.
func DesiredDigest(desired *resourcev1.ResourceDesiredState) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if err := ValidateDesired(desired); err != nil {
		return result, err
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(desired)
	if err != nil {
		return result, err
	}
	h := sha256.New()
	writeHashField(h, []byte("lindm.resource-desired.v1"))
	writeHashField(h, encoded)
	copy(result[:], h.Sum(nil))
	return result, nil
}

// RefEqual compares separate fields; nil never identifies a resource.
func RefEqual(left, right *resourcev1.ResourceRef) bool {
	return left != nil && right != nil && left.GetKind() == right.GetKind() && left.GetCanonicalKey() == right.GetCanonicalKey()
}

func canonicalName(name protoreflect.FullName) string {
	return strings.TrimPrefix(string(name), "lindm.resource.v1.")
}
