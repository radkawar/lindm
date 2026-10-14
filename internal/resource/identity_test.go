// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

const fixtureID = "11111111-1111-4111-8111-111111111111"
const fixtureGeneration = "22222222-2222-4222-8222-222222222222"
const fixtureDevice = `{"deviceId":"` + fixtureID + `","enrollmentGeneration":"` + fixtureGeneration + `"}`
const fixtureDigest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
const fixtureArtifact = `{"sha256":"` + fixtureDigest + `","sizeBytes":"1","artifactId":"` + fixtureID + `"}`
const fixtureRepository = `{"kind":"RESOURCE_KIND_PACKAGE_REPOSITORY","canonicalKey":"apt/` + fixtureID + `"}`

func desiredJSON(t *testing.T, document string) *resourcev1.ResourceDesiredState {
	t.Helper()
	var desired resourcev1.ResourceDesiredState
	if err := protojson.Unmarshal([]byte(document), &desired); err != nil {
		t.Fatal(err)
	}
	ref, err := CanonicalRef(&desired)
	if err != nil {
		t.Fatal(err)
	}
	desired.Ref = ref
	if err := ValidateDesired(&desired); err != nil {
		t.Fatal(err)
	}
	return &desired
}

func TestKindRegistryAndCanonicalIdentity(t *testing.T) {
	certificate := fixtureCertificate(t)
	cases := []struct {
		kind       resourcev1.ResourceKind
		capability string
		document   string
		key        string
	}{
		{1, "systemd.service.v1", `{"systemdService":{"unit":"Example.service","runtime":2,"enablement":1}}`, "Example.service"},
		{2, "local.group.v1", `{"localGroup":{"name":"Operators","presence":1}}`, "Operators"},
		{3, "local.user.v1", `{"localUser":{"name":"Alice","presence":1}}`, "Alice"},
		{4, "sudo.rule.v1", `{"sudoRule":{"ruleId":"` + fixtureID + `","presence":1,"subjects":[{"user":"alice"}],"runAs":[{"user":"root"}],"commands":[{"executable":"/usr/bin/id","arguments":{"noArguments":{}}}],"requirePassword":true}}`, fixtureID},
		{5, "ssh.server.v1", `{"sshServer":{"publicKeyAuthentication":true}}`, "system"},
		{6, "time.sync.v1", `{"timeSync":{"backend":2,"sources":[{"host":{"dns":"time.example.com"},"mode":1,"port":123}],"maxOffsetMilliseconds":100,"convergenceTimeoutSeconds":60}}`, "system"},
		{7, "trust.ca.v1", fmt.Sprintf(`{"trustCa":{"presence":1,"certificateDer":%q,"scope":1,"purposes":[1]}}`, base64.StdEncoding.EncodeToString(certificate)), ""},
		{8, "firewall.zone.v1", `{"firewallZone":{"zoneId":"` + fixtureID + `","presence":1,"defaultIngress":2,"defaultEgress":1}}`, fixtureID},
		{9, "network.connection.v1", `{"networkConnection":{"connectionUuid":"` + fixtureID + `","displayName":"Managed","presence":1,"device":{"permanentMac":"02:00:00:00:00:01"},"activation":1,"ethernet":{}}}`, fixtureID},
		{10, "network.dns.v1", `{"dns":{"connection":{"connectionUuid":"` + fixtureID + `"},"searchDomains":{"names":[]}}}`, "connection/" + fixtureID},
		{11, "network.proxy.v1", `{"proxy":{"scope":{"packages":{}},"direct":{}}}`, "packages"},
		{12, "package.native.v1", `{"nativePackage":{"package":{"ecosystem":1,"nativeName":"Example","architecture":"amd64"},"presence":1,"any":{},"repository":` + fixtureRepository + `,"removal":1}}`, "deb/Example/amd64"},
		{13, "package.repository.v1", `{"repository":{"repositoryId":"` + fixtureID + `","presence":1,"apt":{"uri":"https://packages.example.com/repo","suite":"stable","components":["main"],"architectures":["amd64"],"signingKey":` + fixtureArtifact + `}}}`, "apt/" + fixtureID},
		{14, "flatpak.app.v1", `{"flatpakApp":{"installation":{"system":` + fixtureDevice + `},"appId":"org.example.App","architecture":"x86_64","branch":"stable","presence":1,"remote":{"kind":13,"canonicalKey":"flatpak/` + fixtureID + `"}}}`, "system/" + fixtureID + "/" + fixtureGeneration + "/app/org.example.App/x86_64/stable"},
		{15, "os.update.v1", updateJSON(), "system"},
		{16, "session.policy.v1", `{"sessionPolicy":{"scope":{"systemLogin":` + fixtureDevice + `},"lockOnSuspend":true}}`, "system/login"},
		{17, "password.policy.v1", `{"passwordPolicy":{"minLength":14}}`, "system/local-auth"},
		{18, "snap.app.v1", `{"snapApp":{"name":"example-app","instanceKey":"","presence":1,"channel":"stable","confinement":1}}`, "system/example-app/"},
		{19, "certificate.enrollment.v1", `{"certificateEnrollment":{"credentialId":"` + fixtureID + `","subject":{"device":` + fixtureDevice + `},"issuerProfileId":"` + fixtureID + `","eku":[2],"sans":[{"dns":"device.example.com"}],"key":{"algorithm":1,"software":{}},"renewBeforeSeconds":3600,"consumers":[{"kind":1,"resource":{"kind":9,"canonicalKey":"` + fixtureID + `"}}]}}`, fixtureID + "/device/" + fixtureID + "/" + fixtureGeneration},
		{20, "directory.client.v1", `{"directoryClient":{"backend":1,"realm":"example.com","approvedServers":["dc.example.com"],"login":{"offline":1},"trust":{"certificates":[{"kind":7,"canonicalKey":"system/` + strings.Repeat("0", 64) + `"}]}}}`, "system"},
		{21, "managed.file.v1", `{"managedFile":{"path":"/etc/example/banner","presence":1,"content":"","mode":420,"uid":0,"gid":0}}`, "/etc/example/banner"},
		{22, "sysctl.v1", `{"sysctl":{"key":"net.ipv4.ip_forward","value":"0","persistent":true}}`, "net.ipv4.ip_forward"},
		{23, "systemd.definition.v1", `{"systemdDefinition":{"presence":1,"timer":{"unit":"example.timer","service":{"kind":1,"canonicalKey":"example.service"},"schedule":{"daily":{"hour":4,"minute":30}},"enabled":true}}}`, "timer/example.timer"},
		{23, "systemd.definition.v1", `{"systemdDefinition":{"presence":1,"dropIn":{"unit":"example.service","cpuWeight":100}}}`, "drop-in/example.service"},
		{24, "encryption.compliance.v1", `{"encryptionCompliance":{"requireLuksRoot":true,"requireEscrow":true,"requireTpm":true}}`, "system/root"},
	}
	for _, test := range cases {
		t.Run(test.capability, func(t *testing.T) {
			capability, err := Capability(test.kind)
			if err != nil || capability != test.capability {
				t.Fatalf("capability = %q, %v", capability, err)
			}
			desired := desiredJSON(t, test.document)
			if err := ValidateRef(desired.GetRef()); err != nil {
				t.Fatalf("derived reference rejected: %v", err)
			}
			if desired.GetRef().GetKind() != test.kind {
				t.Fatalf("kind = %v, want %v", desired.GetRef().GetKind(), test.kind)
			}
			if test.key != "" && desired.GetRef().GetCanonicalKey() != test.key {
				t.Fatalf("key = %q, want %q", desired.GetRef().GetCanonicalKey(), test.key)
			}
			if test.kind == resourcev1.ResourceKind_RESOURCE_KIND_TRUST_CA && !strings.HasPrefix(desired.GetRef().GetCanonicalKey(), "system/") {
				t.Fatal("CA identity did not bind the DER fingerprint")
			}
			first, err := DesiredDigest(desired)
			if err != nil {
				t.Fatal(err)
			}
			second, err := DesiredDigest(proto.CloneOf(desired))
			if err != nil || first != second {
				t.Fatalf("non-deterministic desired digest: %v", err)
			}
		})
	}
	for _, kind := range []resourcev1.ResourceKind{0, -1, 25, 1000} {
		if _, err := Capability(kind); err == nil {
			t.Errorf("accepted unknown kind %d", kind)
		}
	}
}

func fixtureCertificate(t *testing.T) []byte {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	certificate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func updateJSON() string {
	return `{"osUpdate":{"selection":1,"maintenance":{"timeZone":"Europe/Berlin","weekdays":[7,3],"localStartMinute":120,"durationMinutes":120},"rebootPolicy":{"mode":2,"maxDelayMinutes":60,"notice":"Updates were installed."},"deferralDays":3}}`
}

func TestCanonicalRefRejectsMismatchesAndUnknownFields(t *testing.T) {
	desired := desiredJSON(t, `{"localGroup":{"name":"Operators","presence":1}}`)
	desired.Ref.CanonicalKey = "operators"
	if err := ValidateDesired(desired); err == nil {
		t.Fatal("case-folded Linux account identity accepted")
	}
	desired.Ref.CanonicalKey = "Operators"
	desired.Ref.Kind = resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER
	if err := ValidateDesired(desired); err == nil {
		t.Fatal("kind/arm mismatch accepted")
	}
	desired.Ref.Kind = resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP
	desired.GetLocalGroup().ProtoReflect().SetUnknown([]byte{0x78, 0x01})
	if err := ValidateDesired(desired); err == nil {
		t.Fatal("nested unknown protobuf field accepted")
	}
	if _, err := CanonicalRef(nil); err == nil {
		t.Fatal("nil desired accepted")
	}
}

func TestDesiredShapeBoundaries(t *testing.T) {
	invalid := []string{
		`{"systemdService":{"unit":"lindm-executor.service","runtime":2,"enablement":1}}`,
		`{"systemdService":{"unit":"example.service","runtime":1,"enablement":1}}`,
		`{"localGroup":{"name":"operators","presence":3}}`,
		`{"localUser":{"name":"alice","presence":2,"homeDirectory":"/home/alice"}}`,
		`{"dns":{"system":{}}}`,
		`{"passwordPolicy":{}}`,
		`{"passwordPolicy":{"minAgeDays":10,"maxAgeDays":1}}`,
		`{"timeSync":{"backend":2,"sources":[{"host":{"dns":"TIME.example.com"},"mode":1,"port":123}],"maxOffsetMilliseconds":1,"convergenceTimeoutSeconds":1}}`,
		`{"firewallZone":{"zoneId":"` + fixtureID + `","presence":1,"defaultIngress":2,"defaultEgress":1,"sourceNetworks":[{"networkAddress":"192.0.2.1","prefixLength":24}]}}`,
		`{"firewallZone":{"zoneId":"` + fixtureID + `","presence":1,"defaultIngress":2,"defaultEgress":1,"rules":[{"ruleId":"` + fixtureID + `","direction":1,"family":1,"protocol":3,"destinationPorts":[{"first":22,"last":22}],"verdict":1}]}}`,
		`{"proxy":{"scope":{"packages":{}},"manual":{"http":{"host":{"dns":"proxy.example.com"},"port":3128},"authentication":{"secretId":"` + fixtureID + `","version":"1","purpose":1,"subjectBindingId":"` + fixtureID + `"}}}}`,
		`{"repository":{"repositoryId":"` + fixtureID + `","presence":1,"rpm":{"nativeId":"example","baseUrls":{"urls":["https://repo.example.com"]},"signingKeys":[` + fixtureArtifact + `],"requireMetadataSignature":false,"requirePackageSignature":true}}}`,
	}
	for _, document := range invalid {
		t.Run(document, func(t *testing.T) {
			var desired resourcev1.ResourceDesiredState
			if err := protojson.Unmarshal([]byte(document), &desired); err != nil {
				t.Fatal(err)
			}
			if _, err := CanonicalRef(&desired); err == nil {
				t.Fatal("invalid desired shape accepted")
			}
		})
	}
}

func TestCanonicalDNSAndCIDR(t *testing.T) {
	name, err := CanonicalDNSName("BÜCHER.Example.")
	if err != nil || name != "xn--bcher-kva.example" {
		t.Fatalf("IDNA identity = %q, %v", name, err)
	}
	for _, name := range []string{"", ".", "example.com.."} {
		if _, err := CanonicalDNSName(name); err == nil {
			t.Errorf("invalid DNS name %q accepted", name)
		}
	}
	prefix, err := CanonicalCIDR(&resourcev1.CIDR{NetworkAddress: "2001:db8::", PrefixLength: 32})
	if err != nil || prefix.String() != "2001:db8::/32" {
		t.Fatalf("IPv6 prefix = %v, %v", prefix, err)
	}
	for _, cidr := range []*resourcev1.CIDR{
		{NetworkAddress: "192.0.2.1", PrefixLength: 24},
		{NetworkAddress: "192.0.2.0", PrefixLength: 33},
		{NetworkAddress: "::ffff:192.0.2.0", PrefixLength: 120},
	} {
		if _, err := CanonicalCIDR(cidr); err == nil {
			t.Errorf("invalid/noncanonical CIDR accepted: %v", cidr)
		}
	}
}

func TestRefDigestSeparatesKindAndKey(t *testing.T) {
	group := &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, CanonicalKey: "same"}
	user := &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: "same"}
	first, err := RefDigest(group)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RefDigest(user)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || RefEqual(group, user) || RefEqual(nil, nil) {
		t.Fatal("kind or nil identity collapsed")
	}
}
