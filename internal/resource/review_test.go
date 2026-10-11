package resource

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestNestedRefsAreCanonicalAndEcosystemBound(t *testing.T) {
	valid := desiredJSON(t, `{"nativePackage":{"package":{"ecosystem":1,"nativeName":"example","architecture":"amd64"},"presence":1,"any":{},"repository":`+fixtureRepository+`,"removal":1}}`)
	for _, key := range []string{
		"apt/AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
		"apt/arbitrary", "rpm/" + fixtureID, "apt/" + fixtureID + "/extra",
	} {
		t.Run(key, func(t *testing.T) {
			desired := proto.CloneOf(valid)
			desired.GetNativePackage().Repository.CanonicalKey = key
			if err := ValidateDesired(desired); err == nil {
				t.Fatal("noncanonical or wrong-ecosystem nested source accepted")
			}
		})
	}
	for _, ref := range []*resourcev1.ResourceRef{
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: "apt/AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_CERTIFICATE_ENROLLMENT, CanonicalKey: fixtureID},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_TRUST_CA, CanonicalKey: "system/" + strings.Repeat("A", 64)},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_DNS, CanonicalKey: "connection/not-a-uuid"},
		{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER, CanonicalKey: "other"},
	} {
		if err := ValidateRef(ref); err == nil {
			t.Errorf("invalid standalone reference accepted: %v", ref)
		}
		if _, err := RefDigest(ref); err == nil {
			t.Errorf("invalid reference digest accepted: %v", ref)
		}
		if _, err := ReleaseClaims(ref); err == nil {
			t.Errorf("invalid reference release accepted: %v", ref)
		}
	}
}

func TestManagedEmptyDNSServersAndUnmanagedServers(t *testing.T) {
	clear := desiredJSON(t, `{"dns":{"system":{},"servers":{}}}`)
	unmanaged := desiredJSON(t, `{"dns":{"system":{},"dnssec":3}}`)
	if clear.GetDns().GetServers() == nil || len(clear.GetDns().GetServers().GetServers()) != 0 {
		t.Fatal("explicit empty managed DNS servers lost presence")
	}
	if unmanaged.GetDns().GetServers() != nil {
		t.Fatal("unmanaged server dimension acquired presence")
	}
	if proto.Equal(clear, unmanaged) {
		t.Fatal("managed-empty and unmanaged DNS states collapsed")
	}
}

func TestUndefinedServiceMaskingRejectedAndDisabledNotStopped(t *testing.T) {
	desired := desiredJSON(t, `{"systemdService":{"unit":"systemd-timesyncd.service","runtime":1,"enablement":3}}`)
	service, err := Claims(desired)
	if err != nil {
		t.Fatal(err)
	}
	timeClaims := claimsJSON(t, `{"timeSync":{"backend":3,"sources":[{"host":{"dns":"time.example.com"},"mode":1,"port":123}],"maxOffsetMilliseconds":100,"convergenceTimeoutSeconds":60}}`)
	if Conflicts(service, timeClaims) {
		t.Fatal("ordinary DISABLED enablement incorrectly means stopped/masked")
	}
	desired.GetSystemdService().Enablement = resourcev1.ServiceEnablement(4)
	if _, err := Claims(desired); err == nil {
		t.Fatal("undefined masking enum admitted")
	}
}

func TestUpdatePolicyClaimsFixedNativeObjects(t *testing.T) {
	claims := claimsJSON(t, updateJSON())
	for _, other := range []string{
		`{"managedFile":{"path":"/etc/dnf/automatic.conf","presence":2}}`,
		`{"managedFile":{"path":"/etc/systemd/system/lindm-os-update.timer","presence":2}}`,
	} {
		if !Conflicts(claims, claimsJSON(t, other)) {
			t.Fatalf("update policy did not exclude another resource on its owned path: %s", other)
		}
	}
	want := map[string]resourcev1.ClaimDomain{"system": resourcev1.ClaimDomain_CLAIM_DOMAIN_UPDATE_SOURCE, "timer/" + OSUpdateTimerUnit: resourcev1.ClaimDomain_CLAIM_DOMAIN_SYSTEMD_DEFINITION}
	for _, kind := range OSUpdateNativeFiles() {
		want[OSUpdateNativePath(kind)] = resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE
	}
	if len(claims) != len(want) {
		t.Fatalf("update policy claims = %d, want %d", len(claims), len(want))
	}
	for _, claim := range claims {
		if want[claim.GetKey()] != claim.GetDomain() || claim.GetMode() != resourcev1.ClaimMode_CLAIM_MODE_VALUE {
			t.Fatalf("unexpected update policy claim %v", claim)
		}
	}
}

func TestUpdatePolicyPlanEffectOnlyForNativeChange(t *testing.T) {
	plan := &resourcev1.ResourcePlan{Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, Plan: &resourcev1.ResourcePlan_OsUpdate{OsUpdate: &resourcev1.OSUpdatePlan{}}}
	if PlanRequiresEffect(plan) {
		t.Fatal("converged update policy requested a native effect")
	}
	plan.GetOsUpdate().TimerChange = true
	if !PlanRequiresEffect(plan) {
		t.Fatal("stopped maintenance timer bypassed the start grant")
	}
	plan.GetOsUpdate().TimerChange = false
	plan.GetOsUpdate().ChangedFiles = []resourcev1.OSUpdateNativeFile{resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY}
	if !PlanRequiresEffect(plan) {
		t.Fatal("changed owned file bypassed the start grant")
	}
	plan.GetOsUpdate().ChangedFiles = nil
	plan.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
	if !PlanRequiresEffect(plan) {
		t.Fatal("release bypassed the start grant")
	}
}

func TestVPNRoutesContributeConflictClaims(t *testing.T) {
	credential := `{"serverTrust":{"certificates":[{"kind":7,"canonicalKey":"system/` + strings.Repeat("0", 64) + `"}]},"serverNames":["vpn.example.com"],"identity":"device","certificate":{"kind":19,"canonicalKey":"` + fixtureID + `/device/` + fixtureID + `/` + fixtureGeneration + `"}}`
	route := `{"destination":{"networkAddress":"198.51.100.0","prefixLength":24},"gateway":"192.0.2.1","metric":10}`
	plugins := []string{
		`"openvpnTls":{"endpoint":{"host":{"dns":"vpn.example.com"},"port":1194},"transport":2,"serverName":"vpn.example.com","credential":` + credential + `,"routes":[` + route + `]}`,
		`"ipsecIkev2":{"endpoint":{"host":{"dns":"vpn.example.com"},"port":500},"remoteIdentity":"vpn.example.com","localIdentity":"device","credential":` + credential + `,"routes":[` + route + `]}`,
	}
	quarantine := claimsJSON(t, `{"firewallZone":{"zoneId":"`+fixtureID+`","presence":1,"defaultIngress":2,"defaultEgress":2}}`)
	otherRoute := []*resourcev1.ResourceClaim{{Domain: resourcev1.ClaimDomain_CLAIM_DOMAIN_NETWORK_ROUTE, Key: "198.51.100.0/24", Mode: resourcev1.ClaimMode_CLAIM_MODE_VALUE, Value: "192.0.2.254/10"}}
	for _, plugin := range plugins {
		vpn := claimsJSON(t, `{"networkConnection":{"connectionUuid":"`+fixtureID+`","displayName":"VPN","presence":1,"device":{"hardwareId":"vpn-adapter"},"activation":2,"vpn":{`+plugin+`}}}`)
		if !Conflicts(vpn, quarantine) || !Conflicts(vpn, otherRoute) {
			t.Fatal("VPN-specific route escaped quarantine or route conflict")
		}
	}
}

func TestEveryObservationArmBindsIdentity(t *testing.T) {
	_, serviceObservation, _ := serviceEvidence(t)
	digest := `"` + fixtureDigest + `"`
	cases := []struct {
		kind     resourcev1.ResourceKind
		key      string
		body     string
		otherKey string
	}{
		{2, "operators", `"localGroup":{"name":"operators","origin":1,"localFileRevision":` + digest + `,"identitySha256":` + digest + `}`, "other"},
		{3, "alice", `"localUser":{"name":"alice","origin":1,"localFileRevision":` + digest + `,"identitySha256":` + digest + `}`, "bob"},
		{4, fixtureID, `"sudoRule":{"ruleId":"` + fixtureID + `","aggregatePolicySha256":` + digest + `}`, fixtureGeneration},
		{5, "system", `"sshServer":{"includeGraphSha256":` + digest + `,"effectiveConfigurationSha256":` + digest + `,"effective":{"port":22},"serviceUnit":"sshd.service"}`, "other"},
		{6, "system", `"timeSync":{"daemonUnit":"chronyd.service","configurationSha256":` + digest + `}`, "other"},
		{7, "system/" + strings.Repeat("0", 64), `"trustCa":{"certificateSha256":` + digest + `,"scope":1,"exportedStoreSha256":` + digest + `}`, "system/" + strings.Repeat("1", 64)},
		{8, fixtureID, `"firewallZone":{"zoneId":"` + fixtureID + `","nativeOwner":"firewalld","nativeVersion":"2","persistentSha256":` + digest + `,"kernelRulesSha256":` + digest + `,"defaultIngress":1,"defaultEgress":1,"nativeIdentitySha256":` + digest + `,"table":"lindm_z_11111111111141118111111111111111","networkNamespaceSha256":` + digest + `}`, fixtureGeneration},
		{9, fixtureID, `"networkConnection":{"connectionUuid":"` + fixtureID + `","medium":1,"settingsSha256":` + digest + `}`, fixtureGeneration},
		{10, "system", `"dns":{"effective":{"system":{},"servers":{}},"nativeOwner":"resolved","persistentSha256":` + digest + `,"runtimeSha256":` + digest + `}`, "connection/" + fixtureID},
		{11, "packages", `"proxy":{"consumer":{"packages":{}},"nativeOwner":"apt","persistentSha256":` + digest + `,"effectiveSha256":` + digest + `}`, "system-environment"},
		{12, "deb/example/amd64", `"nativePackage":{"package":{"ecosystem":1,"nativeName":"example","architecture":"amd64"},"databaseRevisionSha256":` + digest + `}`, "deb/other/amd64"},
		{13, "apt/" + fixtureID, `"repository":{"repositoryId":"` + fixtureID + `","ecosystem":1,"metadataRevisionSha256":` + digest + `,"nativeNamespaceSha256":` + digest + `}`, "apt/" + fixtureGeneration},
		{14, "system/" + fixtureID + "/" + fixtureGeneration + "/app/org.example.App/x86_64/stable", `"flatpakApp":{"installation":{"system":` + fixtureDevice + `},"appId":"org.example.App","architecture":"x86_64","branch":"stable","installationRevisionSha256":` + digest + `}`, "system/" + fixtureID + "/" + fixtureGeneration + "/app/org.example.Other/x86_64/stable"},
		{15, "system", `"osUpdate":{"backend":1,"nativeVersion":"unattended-upgrades 2.9.1+nmu4ubuntu1","files":[{"kind":1,"state":{"path":"/etc/lindm/os-update/policy.binpb","ancestrySha256":` + digest + `}}]}`, "other"},
		{16, "system/login", `"sessionPolicy":{"scope":{"systemLogin":` + fixtureDevice + `},"sessionManager":"logind","effective":{"scope":{"systemLogin":` + fixtureDevice + `},"lockOnSuspend":true},"configurationSha256":` + digest + `}`, "person/" + fixtureID + "/gnome"},
		{17, "system/local-auth", `"passwordPolicy":{"pamOwner":"pam-auth-update","effective":{"minLength":14},"configurationSha256":` + digest + `}`, "other"},
		{18, "system/example/", `"snapApp":{"name":"example","confinement":1,"stateRevisionSha256":` + digest + `}`, "system/other/"},
		{19, fixtureID + "/device/" + fixtureID + "/" + fixtureGeneration, `"certificateEnrollment":{"credentialId":"` + fixtureID + `","subject":{"device":` + fixtureDevice + `}}`, fixtureGeneration + "/device/" + fixtureID + "/" + fixtureGeneration},
		{20, "system", `"directoryClient":{"backend":1,"domain":"example.com","nativeOwner":"sssd","configurationSha256":` + digest + `,"joinIdentitySha256":` + digest + `,"effectiveLogin":{"offline":1}}`, "other"},
		{21, "/etc/example/banner", `"managedFile":{"path":"/etc/example/banner","ancestrySha256":` + digest + `}`, "/etc/example/other"},
		{22, "net.ipv4.ip_forward", `"sysctl":{"key":"net.ipv4.ip_forward","value":"0","persistenceGraphSha256":` + digest + `,"nativeIdentitySha256":` + digest + `,"persistenceFileState":{"path":"/etc/sysctl.d/example.conf","ancestrySha256":` + digest + `}}`, "net.ipv4.conf.all.forwarding"},
		{23, "timer/example.timer", `"systemdDefinition":{"canonicalKey":"timer/example.timer","definitionSha256":` + digest + `,"targetDefinitionSha256":` + digest + `,"timerScheduleSha256":` + digest + `,"fileState":{"path":"/etc/systemd/system/example.timer","ancestrySha256":` + digest + `},"timerEnabled":false,"timerActive":false,"timerInstallProjectionComplete":true}`, "timer/other.timer"},
		{24, "system/root", `"encryptionCompliance":{"evidenceSha256":` + digest + `}`, "system/other"},
	}
	if err := ValidateObservation(serviceObservation); err != nil {
		t.Fatal(err)
	}
	serviceObservation.Ref.CanonicalKey = "other.service"
	if err := ValidateObservation(serviceObservation); err == nil {
		t.Fatal("service evidence substitution accepted")
	}
	for _, test := range cases {
		t.Run(fmt.Sprint(test.kind), func(t *testing.T) {
			var observation resourcev1.ResourceObservation
			if err := protojson.Unmarshal([]byte(`{`+test.body+`}`), &observation); err != nil {
				t.Fatal(err)
			}
			observation.Ref = &resourcev1.ResourceRef{Kind: test.kind, CanonicalKey: test.key}
			observation.Metadata = proto.CloneOf(serviceObservation.GetMetadata())
			if err := ValidateObservation(&observation); err != nil {
				t.Fatalf("valid observation rejected: %v", err)
			}
			observation.Ref.CanonicalKey = test.otherKey
			if err := ValidateObservation(&observation); err == nil {
				t.Fatal("cross-resource observation substitution accepted")
			}
		})
	}
}

func TestPackageRecordCannotSubstituteIdentity(t *testing.T) {
	_, observation, _ := serviceEvidence(t)
	identity := &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, NativeName: "example", Architecture: "amd64"}
	recordIdentity := proto.CloneOf(identity)
	recordIdentity.NativeName = "other"
	observation.Ref = &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "deb/example/amd64"}
	nativeIdentity := sha256.Sum256([]byte("fixture installed other/amd64 1.0 instance 1"))
	observation.Observed = &resourcev1.ResourceObservation_NativePackage{NativePackage: &resourcev1.NativePackageObservation{
		Package: identity, Installed: true, DatabaseRevisionSha256: make([]byte, 32),
		Record: &resourcev1.NativePackageRecord{Package: recordIdentity, Version: &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Deb{Deb: "1.0"}}, NativeIdentitySha256: nativeIdentity[:]},
	}}
	if err := ValidateObservation(observation); err == nil {
		t.Fatal("native package record for a different identity accepted")
	}
}

func TestPackageObservationPreservesUnknownProvenance(t *testing.T) {
	_, observation, _ := serviceEvidence(t)
	identity := &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, NativeName: "example", Architecture: "amd64"}
	nativeIdentity := sha256.Sum256([]byte("fixture installed example/amd64 1.0 instance 1"))
	record := &resourcev1.NativePackageRecord{
		Package:              identity,
		Version:              &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Deb{Deb: "1.0"}},
		NativeIdentitySha256: nativeIdentity[:],
	}
	observation.Ref = &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "deb/example/amd64"}
	observation.Observed = &resourcev1.ResourceObservation_NativePackage{NativePackage: &resourcev1.NativePackageObservation{
		Package: identity, Installed: true, Record: record, DatabaseRevisionSha256: make([]byte, 32),
	}}
	if err := ValidateObservation(observation); err != nil {
		t.Fatalf("native installed package with unknown provenance rejected: %v", err)
	}
	record.Source = &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: "apt/" + fixtureID}
	if err := ValidateObservation(observation); err == nil {
		t.Fatal("unknown provenance accepted an invented source")
	}
	record.ProvenanceKnown = true
	record.SignerSha256, record.MetadataRevisionSha256 = make([]byte, 32), make([]byte, 32)
	if err := ValidateObservation(observation); err != nil {
		t.Fatal(err)
	}
	record.Source.CanonicalKey = "rpm/" + fixtureID
	if err := ValidateObservation(observation); err == nil {
		t.Fatal("known provenance accepted a different package ecosystem")
	}
}
