// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Claims derives conservative resolution constraints, not a native transaction
// preview. Providers must add complete discovered claims before the effect gate.
// No priorities are applied here: cross-kind contradictions always block.
func Claims(desired *resourcev1.ResourceDesiredState) ([]*resourcev1.ResourceClaim, error) {
	if err := ValidateDesired(desired); err != nil {
		return nil, err
	}
	b := &claimBuilder{claims: make([]*resourcev1.ResourceClaim, 0, 4)}
	ref := desired.GetRef().GetCanonicalKey()
	var err error
	switch state := desired.GetState().(type) {
	case *resourcev1.ResourceDesiredState_SystemdService:
		service := state.SystemdService
		if service.GetRuntime() != resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED {
			b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME, service.GetUnit(), resourcev1.ClaimMode_CLAIM_MODE_VALUE, service.GetRuntime().String())
		}
	case *resourcev1.ResourceDesiredState_LocalGroup:
		b.localGroup(state.LocalGroup)
	case *resourcev1.ResourceDesiredState_LocalUser:
		b.localUser(state.LocalUser)
	case *resourcev1.ResourceDesiredState_SudoRule:
		b.sudoRule(state.SudoRule)
	case *resourcev1.ResourceDesiredState_SshServer:
		err = b.sshServer(state.SshServer)
	case *resourcev1.ResourceDesiredState_TimeSync:
		b.timeSync(state.TimeSync.GetBackend())
	case *resourcev1.ResourceDesiredState_TrustCa:
		b.presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_CREDENTIAL, ref, state.TrustCa.GetPresence())
	case *resourcev1.ResourceDesiredState_FirewallZone:
		b.firewallZone(state.FirewallZone)
	case *resourcev1.ResourceDesiredState_NetworkConnection:
		err = b.networkConnection(state.NetworkConnection)
	case *resourcev1.ResourceDesiredState_Dns:
		if connection := state.Dns.GetConnection(); connection != nil {
			b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_CONNECTION, connection.GetConnectionUuid(), resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
		}
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_DNS_OWNER, ref, resourcev1.ClaimMode_CLAIM_MODE_VALUE, "dns-resource")
	case *resourcev1.ResourceDesiredState_NativePackage:
		err = b.nativePackage(state.NativePackage)
	case *resourcev1.ResourceDesiredState_Repository:
		repository := state.Repository
		b.presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_REPOSITORY, ref, repository.GetPresence())
		if repository.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
			b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_REPOSITORY_ALIAS, repositoryAlias(repository), resourcev1.ClaimMode_CLAIM_MODE_VALUE, ref)
		}
	case *resourcev1.ResourceDesiredState_FlatpakApp:
		if state.FlatpakApp.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
			b.requireRef(state.FlatpakApp.GetRemote())
		}
	case *resourcev1.ResourceDesiredState_OsUpdate:
		b.osUpdate(state.OsUpdate)
	case *resourcev1.ResourceDesiredState_PasswordPolicy:
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_PAM_OWNER, "system/local-auth", resourcev1.ClaimMode_CLAIM_MODE_VALUE, "password-policy")
	case *resourcev1.ResourceDesiredState_CertificateEnrollment:
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_CREDENTIAL, ref, resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	case *resourcev1.ResourceDesiredState_DirectoryClient:
		for _, ca := range state.DirectoryClient.GetTrust().GetCertificates() {
			b.requireRef(ca)
		}
	case *resourcev1.ResourceDesiredState_ManagedFile:
		err = b.managedFile(state.ManagedFile)
	case *resourcev1.ResourceDesiredState_Sysctl:
		b.sysctl(state.Sysctl)
	case *resourcev1.ResourceDesiredState_SystemdDefinition:
		err = b.systemdDefinition(ref, state.SystemdDefinition)
	case *resourcev1.ResourceDesiredState_EncryptionCompliance:
		b.encryptionCompliance(state.EncryptionCompliance)
	}
	if err != nil {
		return nil, err
	}
	return b.claims, nil
}

// claimBuilder accumulates one desired state's claims in derivation order.
type claimBuilder struct {
	claims []*resourcev1.ResourceClaim
}

func (b *claimBuilder) add(domain resourcev1.ClaimDomain, key string, mode resourcev1.ClaimMode, value string) {
	b.claims = append(b.claims, &resourcev1.ResourceClaim{Domain: domain, Key: key, Mode: mode, Value: value})
}

func (b *claimBuilder) presence(domain resourcev1.ClaimDomain, key string, state resourcev1.Presence) {
	mode := resourcev1.ClaimMode_CLAIM_MODE_REQUIRED
	if state == resourcev1.Presence_PRESENCE_ABSENT {
		mode = resourcev1.ClaimMode_CLAIM_MODE_FORBIDDEN
	}
	b.add(domain, key, mode, "")
}

func (b *claimBuilder) membership(key string, members *resourcev1.MemberSet) {
	if members == nil {
		return
	}
	if members.GetMode() == resourcev1.SetMode_SET_MODE_EXACT {
		values := slices.Clone(members.GetLocalUserNames())
		slices.Sort(values)
		b.claims = append(b.claims, &resourcev1.ResourceClaim{Domain: resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP_MEMBERSHIP, Key: key, Mode: resourcev1.ClaimMode_CLAIM_MODE_EXACT_SET, Members: values})
	}
	for _, member := range members.GetLocalUserNames() {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP_MEMBERSHIP, key, resourcev1.ClaimMode_CLAIM_MODE_MEMBER, member)
	}
}

func (b *claimBuilder) requireRef(ref *resourcev1.ResourceRef) {
	if ref == nil {
		return
	}
	if domain, ok := existenceDomain(ref.GetKind()); ok {
		b.add(domain, ref.GetCanonicalKey(), resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	}
}

func (b *claimBuilder) routes(routes []*resourcev1.IPRoute) error {
	for _, route := range routes {
		prefix, err := CanonicalCIDR(route.GetDestination())
		if err != nil {
			return err
		}
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_NETWORK_ROUTE, prefix.String(), resourcev1.ClaimMode_CLAIM_MODE_VALUE, fmt.Sprintf("%s/%d", route.GetGateway(), route.GetMetric()))
	}
	return nil
}

func (b *claimBuilder) credential(eap *resourcev1.EAPCredential) {
	if eap == nil {
		return
	}
	b.requireRef(eap.GetCertificate())
	for _, ca := range eap.GetServerTrust().GetCertificates() {
		b.requireRef(ca)
	}
}

func (b *claimBuilder) principal(principal *resourcev1.SudoPrincipal) {
	if principal.GetUser() != "" {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_ACCOUNT, principal.GetUser(), resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	} else {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP, principal.GetGroup(), resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	}
}

func (b *claimBuilder) localGroup(group *resourcev1.LocalGroupDesired) {
	b.presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP, group.GetName(), group.GetPresence())
	b.membership("group:"+group.GetName(), group.GetMembers())
	for _, user := range group.GetMembers().GetLocalUserNames() {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP_MEMBERSHIP, "user:"+user, resourcev1.ClaimMode_CLAIM_MODE_MEMBER, group.GetName())
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_ACCOUNT, user, resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	}
}

func (b *claimBuilder) localUser(user *resourcev1.LocalUserDesired) {
	b.presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_ACCOUNT, user.GetName(), user.GetPresence())
	if user.GetPrimaryGroup() != "" {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP, user.GetPrimaryGroup(), resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	}
	b.membership("user:"+user.GetName(), user.GetSupplementaryGroups())
	for _, group := range user.GetSupplementaryGroups().GetLocalUserNames() {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP_MEMBERSHIP, "group:"+group, resourcev1.ClaimMode_CLAIM_MODE_MEMBER, user.GetName())
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP, group, resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	}
}

func (b *claimBuilder) sudoRule(rule *resourcev1.SudoRuleDesired) {
	if rule.GetPresence() != resourcev1.Presence_PRESENCE_PRESENT {
		return
	}
	for _, principal := range rule.GetSubjects() {
		b.principal(principal)
	}
	for _, principal := range rule.GetRunAs() {
		b.principal(principal)
	}
}

func (b *claimBuilder) sshServer(ssh *resourcev1.SSHServerDesired) error {
	if ssh.PasswordAuthentication != nil && !ssh.GetPasswordAuthentication() && ssh.KeyboardInteractiveAuthentication != nil && !ssh.GetKeyboardInteractiveAuthentication() && ssh.PublicKeyAuthentication != nil && !ssh.GetPublicKeyAuthentication() {
		return errors.New("resource: no_ssh_authentication_mechanism")
	}
	if ssh.GetAllowUsers() != nil && len(ssh.GetAllowUsers().GetNames()) == 0 {
		return errors.New("resource: no_ssh_allowed_users")
	}
	if ssh.GetAllowGroups() != nil && len(ssh.GetAllowGroups().GetNames()) == 0 {
		return errors.New("resource: no_ssh_allowed_groups")
	}
	if ssh.BannerText != nil {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE, SSHBannerPath, resourcev1.ClaimMode_CLAIM_MODE_VALUE, "ssh-banner")
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE, SSHBannerDirectivePath, resourcev1.ClaimMode_CLAIM_MODE_VALUE, "ssh-banner")
	}
	if ssh.Port != nil {
		port := strconv.FormatUint(uint64(ssh.GetPort()), 10)
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_FIREWALL_PORT, "tcp/"+port+"-"+port, resourcev1.ClaimMode_CLAIM_MODE_VALUE, "accept")
	}
	b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, "native-name/openssh-server", resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	return nil
}

// timeSync claims known daemon choices. Unit naming is backend/product-dependent.
// This is a conservative conflict claim, not canonical aliasing.
func (b *claimBuilder) timeSync(backend resourcev1.TimeBackendPreference) {
	active := resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE.String()
	if backend != resourcev1.TimeBackendPreference_TIME_BACKEND_PREFERENCE_TIMESYNCD {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME, "chronyd.service", resourcev1.ClaimMode_CLAIM_MODE_VALUE, active)
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME, "chrony.service", resourcev1.ClaimMode_CLAIM_MODE_VALUE, active)
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, "native-name/chrony", resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	}
	if backend != resourcev1.TimeBackendPreference_TIME_BACKEND_PREFERENCE_CHRONY {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME, "systemd-timesyncd.service", resourcev1.ClaimMode_CLAIM_MODE_VALUE, active)
	}
}

func (b *claimBuilder) firewallZone(zone *resourcev1.FirewallZoneDesired) {
	if zone.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		return
	}
	for _, device := range zone.GetInterfaces() {
		key := "hardware/" + device.GetHardwareId()
		if device.GetPermanentMac() != "" {
			key = "mac/" + device.GetPermanentMac()
		}
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_FIREWALL_INTERFACE, key, resourcev1.ClaimMode_CLAIM_MODE_VALUE, zone.GetZoneId())
	}
	if zone.GetDefaultEgress() != resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT {
		// Route reachability depends on native rule placement and guards;
		// don't pretend an unproven allow exception makes this safe.
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_NETWORK_ROUTE, "*", resourcev1.ClaimMode_CLAIM_MODE_FORBIDDEN, "")
	}
	for _, rule := range zone.GetRules() {
		if rule.GetDirection() != resourcev1.FirewallDirection_FIREWALL_DIRECTION_INPUT || rule.GetProtocol() != resourcev1.IPProtocol_IP_PROTOCOL_TCP {
			continue
		}
		verdict := "deny"
		if rule.GetVerdict() == resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT {
			verdict = "accept"
		}
		for _, ports := range rule.GetDestinationPorts() {
			key := fmt.Sprintf("tcp/%d-%d", ports.GetFirst(), ports.GetLast())
			b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_FIREWALL_PORT, key, resourcev1.ClaimMode_CLAIM_MODE_VALUE, verdict)
		}
	}
}

func (b *claimBuilder) networkConnection(connection *resourcev1.NetworkConnectionDesired) error {
	b.presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_CONNECTION, connection.GetConnectionUuid(), connection.GetPresence())
	if connection.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		return nil
	}
	for _, settings := range []*resourcev1.IPSettings{connection.GetIpv4(), connection.GetIpv6()} {
		if err := b.routes(settings.GetRoutes()); err != nil {
			return err
		}
		if settings.GetGateway() != "" {
			key := "0.0.0.0/0"
			if strings.Contains(settings.GetGateway(), ":") {
				key = "::/0"
			}
			b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_NETWORK_ROUTE, key, resourcev1.ClaimMode_CLAIM_MODE_VALUE, fmt.Sprintf("%s/%d", settings.GetGateway(), settings.GetRouteMetric()))
		}
	}
	b.credential(connection.GetEthernet().GetEap())
	b.credential(connection.GetWifi().GetEap())
	b.credential(connection.GetVpn().GetOpenvpnTls().GetCredential())
	b.credential(connection.GetVpn().GetIpsecIkev2().GetCredential())
	if err := b.routes(connection.GetVpn().GetOpenvpnTls().GetRoutes()); err != nil {
		return err
	}
	return b.routes(connection.GetVpn().GetIpsecIkev2().GetRoutes())
}

// nativePackage claims presence on the row's own key and on the native name.
// A neutral row (`<eco>/<name>`) and a pinned row (`<eco>/<name>/<arch>`) of
// one name never mix in a resolution: on a device whose native architecture is
// the pinned one both would own the same native object under two ledgers.
// Exact versions claim the neutral key so either form detects a disagreement.
func (b *claimBuilder) nativePackage(pkg *resourcev1.NativePackageDesired) error {
	identity := pkg.GetPackage()
	key, neutral := packageKey(identity), neutralPackageKey(identity)
	selector := "explicit"
	if identity.GetArchitecture() == "" {
		selector = "native"
	}
	b.presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, key, pkg.GetPresence())
	b.presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, "native-name/"+identity.GetNativeName(), pkg.GetPresence())
	b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE_SELECTOR, neutral, resourcev1.ClaimMode_CLAIM_MODE_VALUE, selector)
	if pkg.GetPresence() != resourcev1.Presence_PRESENCE_PRESENT {
		return nil
	}
	b.requireRef(pkg.GetRepository())
	if pkg.GetExact() == nil {
		return nil
	}
	digest, err := messageDigest(pkg.GetExact())
	if err != nil {
		return err
	}
	b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, key, resourcev1.ClaimMode_CLAIM_MODE_VALUE, digest)
	if key != neutral {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, neutral, resourcev1.ClaimMode_CLAIM_MODE_VALUE, digest)
	}
	return nil
}

// osUpdate claims the single native update scheduler per device; owned fixed
// paths exclude any managed file or systemd definition resource from the same
// objects.
func (b *claimBuilder) osUpdate(desired *resourcev1.OSUpdateDesired) {
	if desired.GetRollingSnapshot() != nil {
		// A whole-system snapshot cannot honor a separate exact version pin
		// or package removal. Never silently turn those into exclusions.
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, "*", resourcev1.ClaimMode_CLAIM_MODE_VALUE, "rolling-whole-system")
	}
	b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_UPDATE_SOURCE, "system", resourcev1.ClaimMode_CLAIM_MODE_VALUE, "os-update-policy")
	b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_SYSTEMD_DEFINITION, "timer/"+OSUpdateTimerUnit, resourcev1.ClaimMode_CLAIM_MODE_VALUE, "os-update-policy")
	for _, kind := range OSUpdateNativeFiles() {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE, OSUpdateNativePath(kind), resourcev1.ClaimMode_CLAIM_MODE_VALUE, "os-update:"+kind.String())
	}
}

func (b *claimBuilder) managedFile(file *resourcev1.ManagedFileDesired) error {
	b.presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE, file.GetPath(), file.GetPresence())
	if file.GetPresence() != resourcev1.Presence_PRESENCE_PRESENT {
		return nil
	}
	digest, err := messageDigest(file)
	if err != nil {
		return err
	}
	b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE, file.GetPath(), resourcev1.ClaimMode_CLAIM_MODE_VALUE, digest)
	return nil
}

// sysctl hashes bounded public values because claim values are smaller than the
// typed sysctl value bound. Persistence remains a separate claim.
func (b *claimBuilder) sysctl(sysctl *resourcev1.SysctlDesired) {
	digest := sha256.Sum256([]byte(sysctl.GetValue()))
	b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_SYSCTL, sysctl.GetKey(), resourcev1.ClaimMode_CLAIM_MODE_VALUE, hex.EncodeToString(digest[:]))
	if sysctl.GetPersistent() {
		keyDigest := sha256.Sum256([]byte(sysctl.GetKey()))
		path := "/etc/sysctl.d/60-lindm-" + hex.EncodeToString(keyDigest[:]) + ".conf"
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE, path, resourcev1.ClaimMode_CLAIM_MODE_VALUE, "sysctl:"+sysctl.GetKey())
	}
}

func (b *claimBuilder) systemdDefinition(key string, definition *resourcev1.SystemdDefinitionDesired) error {
	b.presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_SYSTEMD_DEFINITION, key, definition.GetPresence())
	path := "/etc/systemd/system/" + definition.GetDropIn().GetUnit() + ".d/60-lindm.conf"
	if timer := definition.GetTimer(); timer != nil {
		path = "/etc/systemd/system/" + timer.GetUnit()
		if definition.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
			b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_SYSTEMD_DEFINITION, "service/"+timer.GetService().GetCanonicalKey(), resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
		}
	}
	b.presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE, path, definition.GetPresence())
	if definition.GetPresence() != resourcev1.Presence_PRESENCE_PRESENT {
		return nil
	}
	digest, err := messageDigest(definition)
	if err != nil {
		return err
	}
	b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_SYSTEMD_DEFINITION, key, resourcev1.ClaimMode_CLAIM_MODE_VALUE, digest)
	b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE, path, resourcev1.ClaimMode_CLAIM_MODE_VALUE, "systemd-definition:"+digest)
	return nil
}

func (b *claimBuilder) encryptionCompliance(compliance *resourcev1.EncryptionComplianceDesired) {
	b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_ENCRYPTION_COMPLIANCE, "system/root/luks", resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	if compliance.GetRequireEscrow() {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_ENCRYPTION_COMPLIANCE, "system/root/escrow", resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	}
	if compliance.GetRequireTpm() {
		b.add(resourcev1.ClaimDomain_CLAIM_DOMAIN_ENCRYPTION_COMPLIANCE, "system/root/tpm", resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	}
}

func existenceDomain(kind resourcev1.ResourceKind) (resourcev1.ClaimDomain, bool) {
	switch kind {
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER:
		return resourcev1.ClaimDomain_CLAIM_DOMAIN_ACCOUNT, true
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP:
		return resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP, true
	case resourcev1.ResourceKind_RESOURCE_KIND_NETWORK_CONNECTION:
		return resourcev1.ClaimDomain_CLAIM_DOMAIN_CONNECTION, true
	case resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE:
		return resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, true
	case resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY:
		return resourcev1.ClaimDomain_CLAIM_DOMAIN_REPOSITORY, true
	case resourcev1.ResourceKind_RESOURCE_KIND_CERTIFICATE_ENROLLMENT, resourcev1.ResourceKind_RESOURCE_KIND_TRUST_CA:
		return resourcev1.ClaimDomain_CLAIM_DOMAIN_CREDENTIAL, true
	case resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE:
		return resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE, true
	case resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION:
		return resourcev1.ClaimDomain_CLAIM_DOMAIN_SYSTEMD_DEFINITION, true
	default:
		return 0, false
	}
}

// ReleaseClaims exposes retained-consumer conflicts before planning ownership-
// safe release. It grants no deletion authority and contains no prior values.
func ReleaseClaims(ref *resourcev1.ResourceRef) ([]*resourcev1.ResourceClaim, error) {
	if _, err := RefDigest(ref); err != nil {
		return nil, err
	}
	domain, ok := existenceDomain(ref.GetKind())
	if !ok {
		return nil, nil
	}
	return []*resourcev1.ResourceClaim{{Domain: domain, Key: ref.GetCanonicalKey(), Mode: resourcev1.ClaimMode_CLAIM_MODE_FORBIDDEN}}, nil
}

// Conflicts tests two independently derived claim sets without precedence.
// Shared identical claims are compatible; incomplete native information must
// still be handled as UNKNOWN by preflight, never inferred supported here.
func Conflicts(left, right []*resourcev1.ResourceClaim) bool {
	for _, a := range left {
		for _, b := range right {
			if a == nil || b == nil {
				return true
			}
			if a.GetDomain() != b.GetDomain() {
				continue
			}
			keysOverlap := a.GetKey() == b.GetKey() || a.GetKey() == "*" || b.GetKey() == "*"
			if a.GetDomain() == resourcev1.ClaimDomain_CLAIM_DOMAIN_FIREWALL_PORT {
				keysOverlap = portClaimsOverlap(a.GetKey(), b.GetKey())
			}
			if keysOverlap && claimConflict(a, b) {
				return true
			}
		}
	}
	return false
}

func claimConflict(a, b *resourcev1.ResourceClaim) bool {
	forbidden := resourcev1.ClaimMode_CLAIM_MODE_FORBIDDEN
	if a.GetMode() == forbidden || b.GetMode() == forbidden {
		return a.GetMode() != b.GetMode()
	}
	if a.GetMode() == resourcev1.ClaimMode_CLAIM_MODE_REQUIRED || b.GetMode() == resourcev1.ClaimMode_CLAIM_MODE_REQUIRED {
		return false
	}
	if a.GetMode() == resourcev1.ClaimMode_CLAIM_MODE_EXACT_SET {
		if b.GetMode() == resourcev1.ClaimMode_CLAIM_MODE_MEMBER {
			return !slices.Contains(a.GetMembers(), b.GetValue())
		}
		if b.GetMode() == resourcev1.ClaimMode_CLAIM_MODE_EXACT_SET {
			return len(a.GetMembers()) != len(b.GetMembers()) || !allMembers(a.GetMembers(), b.GetMembers())
		}
	}
	if b.GetMode() == resourcev1.ClaimMode_CLAIM_MODE_EXACT_SET {
		return claimConflict(b, a)
	}
	if a.GetMode() == resourcev1.ClaimMode_CLAIM_MODE_MEMBER && b.GetMode() == resourcev1.ClaimMode_CLAIM_MODE_MEMBER {
		return false
	}
	return a.GetMode() != b.GetMode() || a.GetValue() != b.GetValue()
}

func allMembers(left, right []string) bool {
	for _, value := range left {
		if !slices.Contains(right, value) {
			return false
		}
	}
	return true
}

func portClaimsOverlap(left, right string) bool {
	leftProtocol, leftRange, ok := strings.Cut(left, "/")
	if !ok {
		return true
	}
	rightProtocol, rightRange, ok := strings.Cut(right, "/")
	if !ok {
		return true
	}
	if leftProtocol != rightProtocol {
		return false
	}
	parse := func(value string) (uint64, uint64, error) {
		first, last, ok := strings.Cut(value, "-")
		if !ok {
			return 0, 0, errors.New("resource: invalid_port_claim")
		}
		start, err := strconv.ParseUint(first, 10, 16)
		if err != nil {
			return 0, 0, err
		}
		end, err := strconv.ParseUint(last, 10, 16)
		return start, end, err
	}
	leftStart, leftEnd, leftErr := parse(leftRange)
	rightStart, rightEnd, rightErr := parse(rightRange)
	return leftErr != nil || rightErr != nil || (leftStart <= rightEnd && rightStart <= leftEnd)
}

func repositoryAlias(repository *resourcev1.RepositoryDesired) string {
	ecosystem := repositoryEcosystem(repository)
	var alias string
	switch source := repository.GetSource().(type) {
	case *resourcev1.RepositoryDesired_Apt:
		// APT merges this source namespace even when contributors request
		// different components or signing keys. Those differences must not
		// evade the cross-resource namespace conflict.
		h := sha256.New()
		writeHashField(h, []byte("lindm.apt-source-namespace.v1"))
		writeHashField(h, []byte(strings.TrimSuffix(source.Apt.GetUri(), "/")))
		writeHashField(h, []byte(source.Apt.GetSuite()))
		alias = hex.EncodeToString(h.Sum(nil))
	case *resourcev1.RepositoryDesired_Rpm:
		alias = source.Rpm.GetNativeId()
	case *resourcev1.RepositoryDesired_Alpm:
		alias = source.Alpm.GetNativeName()
	case *resourcev1.RepositoryDesired_Flatpak:
		alias = source.Flatpak.GetName()
	case *resourcev1.RepositoryDesired_Nix:
		alias = source.Nix.GetApprovedInputId()
	case *resourcev1.RepositoryDesired_Ostree:
		alias = source.Ostree.GetName()
	}
	return ecosystem + "/" + alias
}

func messageDigest(message proto.Message) (string, error) {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
