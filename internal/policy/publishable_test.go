package policy

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// emptySetting places one desired arm with no effective content in a profile.
func emptySetting(t *testing.T, kind int, key, arm, state string) *policyv1.ResourceProfile {
	t.Helper()
	item := resource(resourceA, "unused.service", runtimeActive(), enablementUnmanaged(), nil)
	item.Desired = &resourcev1.ResourceDesiredState{}
	document := fmt.Sprintf(`{"ref":{"kind":%d,"canonicalKey":%q},%q:%s}`, kind, key, arm, state)
	if err := protojson.Unmarshal([]byte(document), item.Desired); err != nil {
		t.Fatalf("%s: %v", arm, err)
	}
	return spec("empty "+arm, item)
}

// Every setting kind refuses its contentless shape before publication: the
// schema refuses most; the publish check refuses the unbound, ruleless zone.
func TestEmptySettingsOfEveryKindAreUnpublishable(t *testing.T) {
	const zone = resourceB
	for _, tc := range []struct {
		kind              int
		arm, state, field string
		rule              string
	}{
		{1, "systemdService", `{"unit":"cups.service","runtime":1,"enablement":1}`, "systemd_service", "systemd_service.managed_dimension"},
		{2, "localGroup", `{"presence":1}`, "local_group.name", "string.min_len"},
		{3, "localUser", `{"presence":1}`, "local_user.name", "string.min_len"},
		{4, "sudoRule", `{"ruleId":"` + zone + `","presence":1}`, "sudo_rule", "sudo_rule.dimension"},
		{5, "sshServer", `{}`, "ssh_server", "ssh_server.dimension"},
		{6, "timeSync", `{"backend":1,"maxOffsetMilliseconds":100,"convergenceTimeoutSeconds":60}`, "time_sync.sources", "repeated.min_items"},
		{7, "trustCa", `{"presence":1,"scope":1,"purposes":[1]}`, "trust_ca.certificate_der", "bytes.min_len"},
		{9, "networkConnection", `{"connectionUuid":"` + zone + `","displayName":"Office","presence":1,"device":{"permanentMac":"02:00:00:00:00:01"},"activation":1}`, "network_connection.medium", "required"},
		{10, "dns", `{"system":{}}`, "dns", "dns.dimension"},
		{11, "proxy", `{"scope":{"packages":{}}}`, "proxy.mode", "required"},
		{12, "nativePackage", `{"package":{"ecosystem":1,"nativeName":"","architecture":"amd64"},"presence":1,"any":{},"repository":{"kind":13,"canonicalKey":"apt/` + zone + `"},"removal":1}`, "native_package.package.native_name", "string.min_len"},
		{13, "repository", `{"repositoryId":"` + zone + `","presence":1,"apt":{}}`, "repository.apt.components", "repeated.min_items"},
		{14, "flatpakApp", `{"presence":1,"architecture":"x86_64","branch":"stable"}`, "flatpak_app.app_id", "string.pattern"},
		{15, "osUpdate", `{}`, "os_update.maintenance", "required"},
		{16, "sessionPolicy", `{"scope":{"systemLogin":{}}}`, "session_policy", "session_policy.dimension"},
		{17, "passwordPolicy", `{}`, "password_policy", "password_policy.dimension"},
		{18, "snapApp", `{"presence":1,"channel":"stable","confinement":1}`, "snap_app.name", "string.min_len"},
		{19, "certificateEnrollment", `{"credentialId":"` + zone + `"}`, "certificate_enrollment.consumers", "repeated.min_items"},
		{20, "directoryClient", `{"backend":1,"realm":"example.com"}`, "directory_client.approved_servers", "repeated.min_items"},
		{21, "managedFile", `{"path":"/etc/lindm-example.conf","presence":1}`, "managed_file", "managed_file.dimensions"},
		{21, "managedFile", `{"path":"/etc/modprobe.d/99-lindm-blocklist.conf","presence":1,"kernelModuleBlocklist":{}}`, "managed_file.kernel_module_blocklist.modules", "repeated.min_items"},
		{22, "sysctl", `{"key":"net.ipv4.ip_forward","value":"","persistent":true}`, "sysctl.value", "string.min_len"},
		{23, "systemdDefinition", `{"presence":1,"dropIn":{"unit":"cups.service"}}`, "systemd_definition.drop_in", "service_drop_in.dimensions"},
		{24, "encryptionCompliance", `{}`, "encryption_compliance.require_luks_root", "bool.const"},
	} {
		t.Run(tc.arm+"/"+tc.rule, func(t *testing.T) {
			err := Validate(t.Context(), emptySetting(t, tc.kind, "unused", tc.arm, tc.state))
			var invalid *protovalidate.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("schema accepted an empty setting: %v", err)
			}
			for _, violation := range invalid.Violations {
				path := protovalidate.FieldPathString(violation.Proto.GetField())
				if violation.Proto.GetRuleId() == tc.rule && strings.HasSuffix(path, "desired."+tc.field) {
					return
				}
			}
			t.Fatalf("missing %s at %s: %v", tc.rule, tc.field, err)
		})
	}

	t.Run("firewallZone", func(t *testing.T) {
		bare := `{"zoneId":"` + zone + `","presence":1,"defaultIngress":2,"defaultEgress":1`
		empty := emptySetting(t, 8, zone, "firewallZone", bare+`}`)
		empty.Resources = append([]*policyv1.ProfileResource{resource(resourceC, "cups.service", runtimeActive(), enablementUnmanaged(), nil)}, empty.Resources...)
		if err := Validate(t.Context(), empty); err != nil {
			t.Fatalf("the schema-valid empty zone is the case this check covers: %v", err)
		}
		var setting *SettingError
		if err := Publishable(empty); !errors.As(err, &setting) || !errors.Is(err, ErrSettingEmpty) {
			t.Fatalf("empty zone publishable: %v", err)
		}
		if setting.Index != 1 || setting.State.Name() != "firewall_zone" {
			t.Fatalf("refusal must identify the caller's setting position and arm: %d %s", setting.Index, setting.State.Name())
		}
		for name, content := range map[string]string{
			"interface": `,"interfaces":[{"permanentMac":"02:00:00:00:00:01"}]}`,
			"network":   `,"sourceNetworks":[{"networkAddress":"0.0.0.0","prefixLength":0},{"networkAddress":"::","prefixLength":0}]}`,
			"rule":      `,"rules":[{"ruleId":"` + resourceD + `","direction":1,"family":1,"protocol":1,"destinationPorts":[{"first":22,"last":22}],"verdict":1}]}`,
		} {
			zoned := emptySetting(t, 8, zone, "firewallZone", bare+content)
			if err := Validate(t.Context(), zoned); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if err := Publishable(zoned); err != nil {
				t.Fatalf("zone with a %s refused: %v", name, err)
			}
		}
		removed := emptySetting(t, 8, zone, "firewallZone", `{"zoneId":"`+zone+`","presence":2,"defaultIngress":2,"defaultEgress":1}`)
		if err := Publishable(removed); err != nil {
			t.Fatalf("zone removal names only its identity: %v", err)
		}
	})
}
