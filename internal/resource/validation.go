package resource

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/protodata"
)

// CanonicalDNSName uses UTS #46 non-transitional lookup, validates DNS labels,
// folds ASCII case and removes one terminal root dot. Roots and empty labels
// are not host identities. No DNS query or locale-dependent folding occurs.
func CanonicalDNSName(name string) (string, error) {
	name = strings.TrimSuffix(name, ".")
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("canonicalize DNS name: %w", err)
	}
	if ascii == "" || strings.HasSuffix(ascii, ".") {
		return "", errors.New("resource: invalid_dns_name")
	}
	return strings.ToLower(ascii), nil
}

// CanonicalCIDR returns the binary-normalized network prefix and rejects host
// bits rather than silently broadening a policy's source or destination range.
func CanonicalCIDR(cidr *resourcev1.CIDR) (netip.Prefix, error) {
	if cidr == nil {
		return netip.Prefix{}, errors.New("resource: missing_cidr")
	}
	address, err := netip.ParseAddr(cidr.GetNetworkAddress())
	if err != nil || address.Zone() != "" || address.Is4In6() {
		return netip.Prefix{}, errors.New("resource: invalid_cidr_address")
	}
	prefix := netip.PrefixFrom(address, int(cidr.GetPrefixLength()))
	if !prefix.IsValid() || prefix != prefix.Masked() {
		return netip.Prefix{}, errors.New("resource: noncanonical_cidr")
	}
	return prefix, nil
}

func validateCanonicalScalars(message protoreflect.Message) error {
	name := canonicalName(message.Descriptor().FullName())
	if ref, ok := message.Interface().(*resourcev1.ResourceRef); ok {
		return ValidateRef(ref)
	}
	switch typed := message.Interface().(type) {
	case *resourcev1.NativePackageDesired:
		if !packageSourceMatches(typed.GetPackage(), typed.GetRepository()) {
			return errors.New("resource: package_repository_ecosystem_mismatch")
		}
	case *resourcev1.NativePackageRecord:
		if typed.GetProvenanceKnown() && !packageSourceMatches(typed.GetPackage(), typed.GetSource()) {
			return errors.New("resource: package_record_ecosystem_mismatch")
		}
	case *resourcev1.PackageTransactionEntry:
		if !packageSourceMatches(typed.GetPackage(), typed.GetSource()) {
			return errors.New("resource: package_transaction_ecosystem_mismatch")
		}
	}
	if name == "CIDR" {
		cidr, ok := message.Interface().(*resourcev1.CIDR)
		if !ok {
			return errors.New("resource: invalid_cidr_type")
		}
		if _, err := CanonicalCIDR(cidr); err != nil {
			return err
		}
	}
	var result error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Message() != nil {
			if field.IsList() {
				list := value.List()
				for i := range list.Len() {
					if result = validateCanonicalScalars(list.Get(i).Message()); result != nil {
						return false
					}
				}
			} else {
				result = validateCanonicalScalars(value.Message())
			}
			return result == nil
		}
		if field.Kind() != protoreflect.StringKind {
			return true
		}
		check := func(text string) error {
			if isIPField(name, string(field.Name())) {
				address, err := netip.ParseAddr(text)
				if err != nil || address.Zone() != "" || address.Is4In6() || address.String() != text {
					return fmt.Errorf("resource: noncanonical_ip in %s", field.FullName())
				}
			}
			if isDNSField(name, string(field.Name())) {
				canonical, err := CanonicalDNSName(text)
				if err != nil || canonical != text {
					return fmt.Errorf("resource: noncanonical_dns in %s", field.FullName())
				}
			}
			if isUUIDField(name, string(field.Name())) {
				canonical, err := canonicalUUID(text)
				if err != nil || canonical != text {
					return fmt.Errorf("resource: noncanonical_uuid in %s", field.FullName())
				}
			}
			return nil
		}
		if field.IsList() {
			list := value.List()
			for i := range list.Len() {
				if result = check(list.Get(i).String()); result != nil {
					return false
				}
			}
		} else {
			result = check(value.String())
		}
		return result == nil
	})
	return result
}

func isIPField(message, field string) bool {
	switch message {
	case "Host", "SubjectAlternativeName":
		return field == "ip"
	case "CIDR":
		return field == "network_address"
	case "IPAddress", "DNSServer":
		return field == "address"
	case "IPRoute", "IPSettings":
		return field == "gateway"
	default:
		return false
	}
}

func isDNSField(message, field string) bool {
	switch message {
	case "Host", "SubjectAlternativeName":
		return field == "dns"
	case "DomainList":
		return field == "names"
	case "DNSServer", "OpenVPNTLS":
		return field == "server_name"
	case "EAPCredential":
		return field == "server_names"
	case "DirectoryClientDesired":
		return field == "realm" || field == "approved_servers"
	default:
		return false
	}
}

func isUUIDField(message, field string) bool {
	switch message {
	case "SecretRef":
		return field == "secret_id" || field == "subject_binding_id"
	case "ArtifactRef":
		return field == "artifact_id"
	case "DeviceBinding":
		return field == "device_id" || field == "enrollment_generation"
	case "NativeAccountBinding":
		return field == "uid_generation"
	case "PersonBinding":
		return field == "assignment_id"
	case "ConnectionScope", "NetworkConnectionDesired":
		return field == "connection_uuid"
	case "SudoRuleDesired", "FirewallRule":
		return field == "rule_id"
	case "FirewallZoneDesired":
		return field == "zone_id"
	case "RepositoryDesired":
		return field == "repository_id"
	case "NixVersion":
		return field == "catalog_id"
	case "NixInput":
		return field == "approved_input_id"
	case "HomePolicy":
		return field == "approved_root_id"
	case "PKCS11Key":
		return field == "approved_token_id"
	case "CertificateEnrollmentDesired":
		return field == "credential_id" || field == "issuer_profile_id"
	case "ReleaseUpgradeTarget":
		return field == "approval_id"
	case "EncryptionComplianceObservation":
		return field == "root_luks_uuid" || field == "root_gpt_disk_guid"
	default:
		return false
	}
}

func validateEnvelope(message proto.Message, limit int) error {
	if message == nil || !message.ProtoReflect().IsValid() {
		return errors.New("resource: missing_envelope")
	}
	if proto.Size(message) > limit {
		return errors.New("resource: envelope_too_large")
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return err
	}
	rules, err := validator()
	if err != nil {
		return err
	}
	if err := rules.Validate(message); err != nil {
		return err
	}
	return validateCanonicalScalars(message.ProtoReflect())
}

// ValidateObservation checks shape and evidence identity without interpreting
// native unknown values as compliance. Time freshness is a consumer decision.
func ValidateObservation(observation *resourcev1.ResourceObservation) error {
	if err := validateEnvelope(observation, MaxObservationBytes); err != nil {
		return err
	}
	ref := observation.GetRef()
	var key string
	var err error
	switch observed := observation.GetObserved().(type) {
	case *resourcev1.ResourceObservation_SystemdService:
		key = observed.SystemdService.GetUnit()
		if observed.SystemdService.GetBootId() != observation.GetMetadata().GetBootId() || !proto.Equal(observed.SystemdService.GetObservedAt(), observation.GetMetadata().GetObservedAt()) {
			return errors.New("resource: service_observation_binding")
		}
	case *resourcev1.ResourceObservation_LocalGroup:
		key = observed.LocalGroup.GetName()
	case *resourcev1.ResourceObservation_LocalUser:
		key = observed.LocalUser.GetName()
	case *resourcev1.ResourceObservation_SudoRule:
		key = observed.SudoRule.GetRuleId()
	case *resourcev1.ResourceObservation_SshServer, *resourcev1.ResourceObservation_TimeSync,
		*resourcev1.ResourceObservation_OsUpdate, *resourcev1.ResourceObservation_DirectoryClient:
		key = "system"
	case *resourcev1.ResourceObservation_TrustCa:
		key = "system/" + hex.EncodeToString(observed.TrustCa.GetCertificateSha256())
	case *resourcev1.ResourceObservation_FirewallZone:
		key = observed.FirewallZone.GetZoneId()
	case *resourcev1.ResourceObservation_NetworkConnection:
		key = observed.NetworkConnection.GetConnectionUuid()
	case *resourcev1.ResourceObservation_Dns:
		key = "system"
		if connection := observed.Dns.GetEffective().GetConnection(); connection != nil {
			key = "connection/" + connection.GetConnectionUuid()
		}
	case *resourcev1.ResourceObservation_Proxy:
		switch scope := observed.Proxy.GetConsumer().GetConsumer().(type) {
		case *resourcev1.ProxyConsumer_Packages:
			key = "packages"
		case *resourcev1.ProxyConsumer_SystemEnvironment:
			key = "system-environment"
		case *resourcev1.ProxyConsumer_Person:
			key, err = desktopKey(scope.Person)
		}
	case *resourcev1.ResourceObservation_NativePackage:
		observedPackage := observed.NativePackage.GetPackage()
		key = packageKey(observedPackage)
		// Evidence always names the resolved architecture (protovalidate); a
		// neutral ref accepts whichever one this device resolved.
		if neutral := neutralPackageKey(observedPackage); ref.GetCanonicalKey() == neutral {
			key = neutral
		}
		if record := observed.NativePackage.GetRecord(); record != nil && !proto.Equal(record.GetPackage(), observedPackage) {
			return errors.New("resource: package_record_identity_mismatch")
		}
	case *resourcev1.ResourceObservation_Repository:
		ecosystem := strings.ToLower(strings.TrimPrefix(observed.Repository.GetEcosystem().String(), "REPOSITORY_ECOSYSTEM_"))
		key = ecosystem + "/" + observed.Repository.GetRepositoryId()
	case *resourcev1.ResourceObservation_FlatpakApp:
		app := observed.FlatpakApp
		key, err = installationKey(app.GetInstallation())
		key += "/app/" + app.GetAppId() + "/" + app.GetArchitecture() + "/" + app.GetBranch()
	case *resourcev1.ResourceObservation_SessionPolicy:
		if !proto.Equal(observed.SessionPolicy.GetScope(), observed.SessionPolicy.GetEffective().GetScope()) {
			return errors.New("resource: session_scope_mismatch")
		}
		key = "system/login"
		if person := observed.SessionPolicy.GetScope().GetPersonDesktop(); person != nil {
			key, err = desktopKey(person)
		}
	case *resourcev1.ResourceObservation_PasswordPolicy:
		key = "system/local-auth"
	case *resourcev1.ResourceObservation_SnapApp:
		key = "system/" + observed.SnapApp.GetName() + "/" + observed.SnapApp.GetInstanceKey()
	case *resourcev1.ResourceObservation_CertificateEnrollment:
		key, err = subjectKey(observed.CertificateEnrollment.GetSubject())
		key = observed.CertificateEnrollment.GetCredentialId() + "/" + key
	case *resourcev1.ResourceObservation_ManagedFile:
		key = observed.ManagedFile.GetPath()
	case *resourcev1.ResourceObservation_Sysctl:
		key = observed.Sysctl.GetKey()
	case *resourcev1.ResourceObservation_SystemdDefinition:
		key = observed.SystemdDefinition.GetCanonicalKey()
		if effective := observed.SystemdDefinition.GetEffective(); effective != nil && systemdDefinitionKey(effective) != key {
			return errors.New("resource: definition_observation_identity_mismatch")
		}
	case *resourcev1.ResourceObservation_EncryptionCompliance:
		key = "system/root"
	default:
		return errors.New("resource: unknown_observation_arm")
	}
	if err != nil {
		return err
	}
	if key != ref.GetCanonicalKey() {
		return errors.New("resource: observation_identity_mismatch")
	}
	return nil
}

// ValidatePlan binds canonical desired and before evidence to the envelope.
// Native locks, ledger custody and actual inverse remain executor checks.
func ValidatePlan(plan *resourcev1.ResourcePlan) error {
	if err := validateEnvelope(plan, MaxPlanBytes); err != nil {
		return err
	}
	message := plan.ProtoReflect()
	arm := message.WhichOneof(message.Descriptor().Oneofs().ByName("plan"))
	native := message.Get(arm).Message()
	digest, err := DesiredDigest(PlanDesired(plan))
	if err != nil {
		return err
	}
	if !bytes.Equal(digest[:], plan.GetDesiredSha256()) {
		return errors.New("resource: plan_desired_digest_mismatch")
	}
	if !RefEqual(plan.GetRef(), plan.GetBefore().GetRef()) || !proto.Equal(plan.GetBackend(), plan.GetBefore().GetMetadata().GetBackend()) {
		return errors.New("resource: plan_observation_binding_mismatch")
	}
	observationDigest, err := ObservationDigest(plan.GetBefore())
	if err != nil {
		return err
	}
	if !bytes.Equal(observationDigest[:], plan.GetObservationSha256()) {
		return errors.New("resource: plan_observation_digest_mismatch")
	}
	if beforeField := native.Descriptor().Fields().ByName("before"); beforeField != nil {
		beforeMessage := plan.GetBefore().ProtoReflect()
		observedField := beforeMessage.WhichOneof(beforeMessage.Descriptor().Oneofs().ByName("observed"))
		if !proto.Equal(native.Get(beforeField).Message().Interface(), beforeMessage.Get(observedField).Message().Interface()) {
			return errors.New("resource: plan_typed_before_mismatch")
		}
	}
	inverseField := native.Descriptor().Fields().ByName("inverse")
	if inverseField != nil && native.Has(inverseField) {
		inverse := native.Get(inverseField).Message()
		revision := inverse.Get(inverse.Descriptor().Fields().ByName("ledger_revision_sha256")).Bytes()
		if !bytes.Equal(revision, plan.GetOwnershipRevisionSha256()) {
			return errors.New("resource: inverse_ledger_revision_mismatch")
		}
	}
	return nil
}

// ValidateVerification rejects mismatched refs and non-native convergence;
// callers additionally bind these digests to their admitted action and freshness.
func ValidateVerification(verification *resourcev1.ResourceVerification) error {
	if err := validateEnvelope(verification, MaxVerificationBytes); err != nil {
		return err
	}
	return ValidateObservation(verification.GetAfter())
}
