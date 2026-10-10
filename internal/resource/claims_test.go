package resource

import (
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func claimsJSON(t *testing.T, document string) []*resourcev1.ResourceClaim {
	t.Helper()
	claims, err := Claims(desiredJSON(t, document))
	if err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestCrossKindClaimConflicts(t *testing.T) {
	const packageIdentity = `{"ecosystem":1,"nativeName":"chrony","architecture":"amd64"}`
	const connection = `{"networkConnection":{"connectionUuid":"` + fixtureID + `","displayName":"Managed","presence":1,"device":{"permanentMac":"02:00:00:00:00:01"},"activation":2,"ipv4":{"method":2,"addresses":[{"address":"192.0.2.2","prefixLength":24}],"routes":[{"destination":{"networkAddress":"198.51.100.0","prefixLength":24},"gateway":"192.0.2.1","metric":10}]},"ethernet":{}}}`
	const pinnedPackage = `{"nativePackage":{"package":` + packageIdentity + `,"presence":1,"exact":{"deb":"1.0-1"},"repository":` + fixtureRepository + `,"removal":1}}`
	cases := []struct {
		name     string
		left     string
		right    string
		conflict bool
	}{
		{"stopped clock daemon", `{"systemdService":{"unit":"chronyd.service","runtime":3,"enablement":1}}`, `{"timeSync":{"backend":2,"sources":[{"host":{"dns":"time.example.com"},"mode":1,"port":123}],"maxOffsetMilliseconds":100,"convergenceTimeoutSeconds":60}}`, true},
		{"active clock daemon agrees", `{"systemdService":{"unit":"chronyd.service","runtime":2,"enablement":1}}`, `{"timeSync":{"backend":2,"sources":[{"host":{"dns":"time.example.com"},"mode":1,"port":123}],"maxOffsetMilliseconds":100,"convergenceTimeoutSeconds":60}}`, false},
		{"group excludes user membership", `{"localGroup":{"name":"operators","presence":1,"members":{"localUserNames":["alice"],"mode":2}}}`, `{"localUser":{"name":"bob","presence":1,"supplementaryGroups":{"localUserNames":["operators"],"mode":1}}}`, true},
		{"exact empty group excludes membership", `{"localGroup":{"name":"operators","presence":1,"members":{"mode":2}}}`, `{"localUser":{"name":"bob","presence":1,"supplementaryGroups":{"localUserNames":["operators"],"mode":1}}}`, true},
		{"user excludes group membership", `{"localGroup":{"name":"operators","presence":1,"members":{"localUserNames":["alice"],"mode":1}}}`, `{"localUser":{"name":"alice","presence":1,"supplementaryGroups":{"localUserNames":["staff"],"mode":2}}}`, true},
		{"additive group permits other user", `{"localGroup":{"name":"operators","presence":1,"members":{"localUserNames":["alice"],"mode":1}}}`, `{"localUser":{"name":"bob","presence":1,"supplementaryGroups":{"localUserNames":["operators"],"mode":1}}}`, false},
		{"removed primary group", `{"localGroup":{"name":"operators","presence":2}}`, `{"localUser":{"name":"alice","presence":1,"primaryGroup":"operators"}}`, true},
		{"two zones bind same interface", `{"firewallZone":{"zoneId":"` + fixtureID + `","presence":1,"interfaces":[{"permanentMac":"02:00:00:00:00:01"}],"defaultIngress":1,"defaultEgress":1}}`, `{"firewallZone":{"zoneId":"` + fixtureGeneration + `","presence":1,"interfaces":[{"permanentMac":"02:00:00:00:00:01"}],"defaultIngress":2,"defaultEgress":1}}`, true},
		{"static route and quarantine", connection, `{"firewallZone":{"zoneId":"` + fixtureID + `","presence":1,"defaultIngress":2,"defaultEgress":2}}`, true},
		{"administration port denied", `{"sshServer":{"port":22}}`, `{"firewallZone":{"zoneId":"` + fixtureID + `","presence":1,"defaultIngress":1,"defaultEgress":1,"rules":[{"ruleId":"` + fixtureID + `","direction":1,"family":1,"protocol":1,"destinationPorts":[{"first":1,"last":1024}],"verdict":2}]}}`, true},
		{"unrelated firewall port", `{"sshServer":{"port":22}}`, `{"firewallZone":{"zoneId":"` + fixtureID + `","presence":1,"defaultIngress":1,"defaultEgress":1,"rules":[{"ruleId":"` + fixtureID + `","direction":1,"family":1,"protocol":1,"destinationPorts":[{"first":80,"last":80}],"verdict":2}]}}`, false},
		{"update encompasses pinned package", pinnedPackage, updateJSON(""), true},
		{"update excludes pinned package", pinnedPackage, updateJSON(packageIdentity), false},
		{"remove configured daemon package", `{"nativePackage":{"package":` + packageIdentity + `,"presence":2,"any":{},"repository":` + fixtureRepository + `,"removal":1}}`, `{"timeSync":{"backend":2,"sources":[{"host":{"dns":"time.example.com"},"mode":1,"port":123}],"maxOffsetMilliseconds":100,"convergenceTimeoutSeconds":60}}`, true},
		{"dns retains deleted connection", `{"dns":{"connection":{"connectionUuid":"` + fixtureID + `"},"ignoreAutoDns":true}}`, `{"networkConnection":{"connectionUuid":"` + fixtureID + `","displayName":"Managed","presence":2,"device":{"permanentMac":"02:00:00:00:00:01"},"activation":1,"ethernet":{}}}`, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			left, right := claimsJSON(t, test.left), claimsJSON(t, test.right)
			if actual := Conflicts(left, right); actual != test.conflict {
				t.Fatalf("conflict = %v, want %v", actual, test.conflict)
			}
			if actual := Conflicts(right, left); actual != test.conflict {
				t.Fatalf("reversed conflict = %v, want %v", actual, test.conflict)
			}
		})
	}
}

func TestSSHRejectsNoAdministrationMechanism(t *testing.T) {
	desired := desiredJSON(t, `{"sshServer":{"passwordAuthentication":false,"keyboardInteractiveAuthentication":false,"publicKeyAuthentication":false}}`)
	if _, err := Claims(desired); err == nil {
		t.Fatal("all administration authentication mechanisms disabled without conflict")
	}
}

func TestCredentialReleaseConflictsWithRetainedVPN(t *testing.T) {
	credentialKey := fixtureID + "/device/" + fixtureID + "/" + fixtureGeneration
	vpn := desiredJSON(t, `{"networkConnection":{"connectionUuid":"`+fixtureID+`","displayName":"VPN","presence":1,"device":{"hardwareId":"approved-vpn-adapter"},"activation":2,"vpn":{"openvpnTls":{"endpoint":{"host":{"dns":"vpn.example.com"},"port":1194},"transport":2,"serverName":"vpn.example.com","credential":{"serverTrust":{"certificates":[{"kind":7,"canonicalKey":"system/0000000000000000000000000000000000000000000000000000000000000000"}]},"serverNames":["vpn.example.com"],"identity":"device","certificate":{"kind":19,"canonicalKey":"`+credentialKey+`"}}}}}}`)
	claims, err := Claims(vpn)
	if err != nil {
		t.Fatal(err)
	}
	release, err := ReleaseClaims(&resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_CERTIFICATE_ENROLLMENT, CanonicalKey: credentialKey})
	if err != nil {
		t.Fatal(err)
	}
	if !Conflicts(claims, release) || !Conflicts(release, claims) {
		t.Fatal("credential release did not retain the VPN dependency")
	}
}

func TestClaimEqualityAndInputImmutability(t *testing.T) {
	desired := desiredJSON(t, `{"localGroup":{"name":"operators","presence":1,"members":{"localUserNames":["zulu","alice"],"mode":2}}}`)
	before := proto.CloneOf(desired)
	claims, err := Claims(desired)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(desired, before) {
		t.Fatal("claim derivation mutated immutable desired input")
	}
	if Conflicts(claims, claims) {
		t.Fatal("identical contributors conflict")
	}
	if Conflicts(nil, nil) {
		t.Fatal("empty claim sets conflict")
	}
}

func TestTransactionRemovalConflictsWithPinnedPackage(t *testing.T) {
	pin := claimsJSON(t, `{"nativePackage":{"package":{"ecosystem":1,"nativeName":"example","architecture":"amd64"},"presence":1,"exact":{"deb":"1.0-1"},"repository":`+fixtureRepository+`,"removal":1}}`)
	// A native solver must contribute every package removal, including side
	// effects of a system update. This does not mock an actual solver execution.
	removal := []*resourcev1.ResourceClaim{{Domain: resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, Key: "deb/example/amd64", Mode: resourcev1.ClaimMode_CLAIM_MODE_FORBIDDEN}}
	if !Conflicts(pin, removal) {
		t.Fatal("OS solver removal bypassed a retained package pin")
	}
}
