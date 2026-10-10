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
	claims := make([]*resourcev1.ResourceClaim, 0, 4)
	add := func(domain resourcev1.ClaimDomain, key string, mode resourcev1.ClaimMode, value string) {
		claims = append(claims, &resourcev1.ResourceClaim{Domain: domain, Key: key, Mode: mode, Value: value})
	}
	presence := func(domain resourcev1.ClaimDomain, key string, state resourcev1.Presence) {
		mode := resourcev1.ClaimMode_CLAIM_MODE_REQUIRED
		if state == resourcev1.Presence_PRESENCE_ABSENT {
			mode = resourcev1.ClaimMode_CLAIM_MODE_FORBIDDEN
		}
		add(domain, key, mode, "")
	}
	membership := func(key string, members *resourcev1.MemberSet) {
		if members == nil {
			return
		}
		if members.GetMode() == resourcev1.SetMode_SET_MODE_EXACT {
			values := slices.Clone(members.GetLocalUserNames())
			slices.Sort(values)
			claims = append(claims, &resourcev1.ResourceClaim{Domain: resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP_MEMBERSHIP, Key: key, Mode: resourcev1.ClaimMode_CLAIM_MODE_EXACT_SET, Members: values})
		}
		for _, member := range members.GetLocalUserNames() {
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP_MEMBERSHIP, key, resourcev1.ClaimMode_CLAIM_MODE_MEMBER, member)
		}
	}
	requireRef := func(ref *resourcev1.ResourceRef) {
		if ref == nil {
			return
		}
		domain, ok := existenceDomain(ref.GetKind())
		if ok {
			add(domain, ref.GetCanonicalKey(), resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
		}
	}
	routeClaims := func(routes []*resourcev1.IPRoute) error {
		for _, route := range routes {
			prefix, err := CanonicalCIDR(route.GetDestination())
			if err != nil {
				return err
			}
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_NETWORK_ROUTE, prefix.String(), resourcev1.ClaimMode_CLAIM_MODE_VALUE, fmt.Sprintf("%s/%d", route.GetGateway(), route.GetMetric()))
		}
		return nil
	}
	credential := func(eap *resourcev1.EAPCredential) {
		if eap != nil {
			requireRef(eap.GetCertificate())
			for _, ca := range eap.GetServerTrust().GetCertificates() {
				requireRef(ca)
			}
		}
	}
	switch state := desired.GetState().(type) {
	case *resourcev1.ResourceDesiredState_SystemdService:
		service := state.SystemdService
		if service.GetRuntime() != resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED {
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME, service.GetUnit(), resourcev1.ClaimMode_CLAIM_MODE_VALUE, service.GetRuntime().String())
		}
	case *resourcev1.ResourceDesiredState_LocalGroup:
		group := state.LocalGroup
		presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP, group.GetName(), group.GetPresence())
		membership("group:"+group.GetName(), group.GetMembers())
		for _, user := range group.GetMembers().GetLocalUserNames() {
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP_MEMBERSHIP, "user:"+user, resourcev1.ClaimMode_CLAIM_MODE_MEMBER, group.GetName())
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_ACCOUNT, user, resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
		}
	case *resourcev1.ResourceDesiredState_LocalUser:
		user := state.LocalUser
		presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_ACCOUNT, user.GetName(), user.GetPresence())
		if user.GetPrimaryGroup() != "" {
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP, user.GetPrimaryGroup(), resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
		}
		membership("user:"+user.GetName(), user.GetSupplementaryGroups())
		for _, group := range user.GetSupplementaryGroups().GetLocalUserNames() {
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP_MEMBERSHIP, "group:"+group, resourcev1.ClaimMode_CLAIM_MODE_MEMBER, user.GetName())
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP, group, resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
		}
	case *resourcev1.ResourceDesiredState_SudoRule:
		if state.SudoRule.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
			for _, principal := range state.SudoRule.GetSubjects() {
				claimPrincipal(principal, add)
			}
			for _, principal := range state.SudoRule.GetRunAs() {
				claimPrincipal(principal, add)
			}
		}
	case *resourcev1.ResourceDesiredState_SshServer:
		ssh := state.SshServer
		if ssh.PasswordAuthentication != nil && !ssh.GetPasswordAuthentication() && ssh.KeyboardInteractiveAuthentication != nil && !ssh.GetKeyboardInteractiveAuthentication() && ssh.PublicKeyAuthentication != nil && !ssh.GetPublicKeyAuthentication() {
			return nil, errors.New("resource: no_ssh_authentication_mechanism")
		}
		if ssh.GetAllowUsers() != nil && len(ssh.GetAllowUsers().GetNames()) == 0 {
			return nil, errors.New("resource: no_ssh_allowed_users")
		}
		if ssh.GetAllowGroups() != nil && len(ssh.GetAllowGroups().GetNames()) == 0 {
			return nil, errors.New("resource: no_ssh_allowed_groups")
		}
		if ssh.Port != nil {
			port := strconv.FormatUint(uint64(ssh.GetPort()), 10)
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_FIREWALL_PORT, "tcp/"+port+"-"+port, resourcev1.ClaimMode_CLAIM_MODE_VALUE, "accept")
		}
		add(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, "native-name/openssh-server", resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	case *resourcev1.ResourceDesiredState_TimeSync:
		// Unit naming is backend/product-dependent. This is a conservative
		// conflict claim over known daemon choices, not canonical aliasing.
		backend := state.TimeSync.GetBackend()
		if backend != resourcev1.TimeBackendPreference_TIME_BACKEND_PREFERENCE_TIMESYNCD {
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME, "chronyd.service", resourcev1.ClaimMode_CLAIM_MODE_VALUE, resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE.String())
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME, "chrony.service", resourcev1.ClaimMode_CLAIM_MODE_VALUE, resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE.String())
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, "native-name/chrony", resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
		}
		if backend != resourcev1.TimeBackendPreference_TIME_BACKEND_PREFERENCE_CHRONY {
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME, "systemd-timesyncd.service", resourcev1.ClaimMode_CLAIM_MODE_VALUE, resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE.String())
		}
	case *resourcev1.ResourceDesiredState_TrustCa:
		presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_CREDENTIAL, desired.GetRef().GetCanonicalKey(), state.TrustCa.GetPresence())
	case *resourcev1.ResourceDesiredState_FirewallZone:
		zone := state.FirewallZone
		if zone.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
			break
		}
		for _, device := range zone.GetInterfaces() {
			key := "hardware/" + device.GetHardwareId()
			if device.GetPermanentMac() != "" {
				key = "mac/" + device.GetPermanentMac()
			}
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_FIREWALL_INTERFACE, key, resourcev1.ClaimMode_CLAIM_MODE_VALUE, zone.GetZoneId())
		}
		if zone.GetDefaultEgress() != resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT {
			// Route reachability depends on native rule placement and guards;
			// don't pretend an unproven allow exception makes this safe.
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_NETWORK_ROUTE, "*", resourcev1.ClaimMode_CLAIM_MODE_FORBIDDEN, "")
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
				add(resourcev1.ClaimDomain_CLAIM_DOMAIN_FIREWALL_PORT, key, resourcev1.ClaimMode_CLAIM_MODE_VALUE, verdict)
			}
		}
	case *resourcev1.ResourceDesiredState_NetworkConnection:
		connection := state.NetworkConnection
		presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_CONNECTION, connection.GetConnectionUuid(), connection.GetPresence())
		if connection.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
			break
		}
		for _, settings := range []*resourcev1.IPSettings{connection.GetIpv4(), connection.GetIpv6()} {
			if err := routeClaims(settings.GetRoutes()); err != nil {
				return nil, err
			}
			if settings.GetGateway() != "" {
				key := "0.0.0.0/0"
				if strings.Contains(settings.GetGateway(), ":") {
					key = "::/0"
				}
				add(resourcev1.ClaimDomain_CLAIM_DOMAIN_NETWORK_ROUTE, key, resourcev1.ClaimMode_CLAIM_MODE_VALUE, fmt.Sprintf("%s/%d", settings.GetGateway(), settings.GetRouteMetric()))
			}
		}
		credential(connection.GetEthernet().GetEap())
		credential(connection.GetWifi().GetEap())
		credential(connection.GetVpn().GetOpenvpnTls().GetCredential())
		credential(connection.GetVpn().GetIpsecIkev2().GetCredential())
		if err := routeClaims(connection.GetVpn().GetOpenvpnTls().GetRoutes()); err != nil {
			return nil, err
		}
		if err := routeClaims(connection.GetVpn().GetIpsecIkev2().GetRoutes()); err != nil {
			return nil, err
		}
	case *resourcev1.ResourceDesiredState_Dns:
		if connection := state.Dns.GetConnection(); connection != nil {
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_CONNECTION, connection.GetConnectionUuid(), resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
		}
		add(resourcev1.ClaimDomain_CLAIM_DOMAIN_DNS_OWNER, desired.GetRef().GetCanonicalKey(), resourcev1.ClaimMode_CLAIM_MODE_VALUE, "dns-resource")
	case *resourcev1.ResourceDesiredState_NativePackage:
		pkg := state.NativePackage
		key := packageKey(pkg.GetPackage())
		presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, key, pkg.GetPresence())
		presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, "native-name/"+pkg.GetPackage().GetNativeName(), pkg.GetPresence())
		if pkg.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
			requireRef(pkg.GetRepository())
			if pkg.GetExact() != nil {
				digest, err := messageDigest(pkg.GetExact())
				if err != nil {
					return nil, err
				}
				add(resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, key, resourcev1.ClaimMode_CLAIM_MODE_VALUE, digest)
			}
		}
	case *resourcev1.ResourceDesiredState_Repository:
		repository := state.Repository
		presence(resourcev1.ClaimDomain_CLAIM_DOMAIN_REPOSITORY, desired.GetRef().GetCanonicalKey(), repository.GetPresence())
		if repository.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
			alias := repositoryAlias(repository)
			add(resourcev1.ClaimDomain_CLAIM_DOMAIN_REPOSITORY_ALIAS, alias, resourcev1.ClaimMode_CLAIM_MODE_VALUE, desired.GetRef().GetCanonicalKey())
		}
	case *resourcev1.ResourceDesiredState_FlatpakApp:
		if state.FlatpakApp.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
			requireRef(state.FlatpakApp.GetRemote())
		}
	case *resourcev1.ResourceDesiredState_OsUpdate:
		// Exact package pins must be excluded from an unplanned system update.
		// A native solver manifest may refine the complete member claims later.
		members := make([]string, 0, len(state.OsUpdate.GetExclusions()))
		for _, pkg := range state.OsUpdate.GetExclusions() {
			members = append(members, packageKey(pkg))
		}
		slices.Sort(members)
		claims = append(claims, &resourcev1.ResourceClaim{Domain: resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, Key: "*", Mode: resourcev1.ClaimMode_CLAIM_MODE_EXACT_SET, Members: members})
		for _, snapshot := range state.OsUpdate.GetSource().GetRepositories().GetRepositories() {
			requireRef(snapshot.GetRepository())
		}
		requireRef(state.OsUpdate.GetSource().GetOstree().GetRemote())
	case *resourcev1.ResourceDesiredState_PasswordPolicy:
		add(resourcev1.ClaimDomain_CLAIM_DOMAIN_PAM_OWNER, "system/local-auth", resourcev1.ClaimMode_CLAIM_MODE_VALUE, "password-policy")
	case *resourcev1.ResourceDesiredState_CertificateEnrollment:
		add(resourcev1.ClaimDomain_CLAIM_DOMAIN_CREDENTIAL, desired.GetRef().GetCanonicalKey(), resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	case *resourcev1.ResourceDesiredState_DirectoryClient:
		for _, ca := range state.DirectoryClient.GetTrust().GetCertificates() {
			requireRef(ca)
		}
	}
	return claims, nil
}

func claimPrincipal(principal *resourcev1.SudoPrincipal, add func(resourcev1.ClaimDomain, string, resourcev1.ClaimMode, string)) {
	if principal.GetUser() != "" {
		add(resourcev1.ClaimDomain_CLAIM_DOMAIN_ACCOUNT, principal.GetUser(), resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
	} else {
		add(resourcev1.ClaimDomain_CLAIM_DOMAIN_GROUP, principal.GetGroup(), resourcev1.ClaimMode_CLAIM_MODE_REQUIRED, "")
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
			if a.GetDomain() == resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE && (a.GetKey() == "*" || b.GetKey() == "*") {
				if updatePinConflict(a, b) || updatePinConflict(b, a) {
					return true
				}
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

func updatePinConflict(update, pin *resourcev1.ResourceClaim) bool {
	return update.GetKey() == "*" && update.GetMode() == resourcev1.ClaimMode_CLAIM_MODE_EXACT_SET && pin.GetMode() == resourcev1.ClaimMode_CLAIM_MODE_VALUE && !slices.Contains(update.GetMembers(), pin.GetKey())
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
