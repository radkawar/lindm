// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// These tests cover public contract rejection and binding, not native provider
// safety or platform qualification. Unsafe native domains are provider checks.
func TestHostDesiredRejectsUnsafeShapes(t *testing.T) {
	cases := []string{
		`{"managedFile":{"path":"relative","presence":2}}`,
		`{"managedFile":{"path":"/etc/../shadow","presence":2}}`,
		`{"managedFile":{"path":"/etc/./example","presence":2}}`,
		`{"managedFile":{"path":"/etc//example","presence":2}}`,
		`{"managedFile":{"path":"/etc/example/","presence":2}}`,
		`{"managedFile":{"path":"/etc/example","presence":1}}`,
		`{"managedFile":{"path":"/etc/example","presence":1,"mode":512}}`,
		`{"managedFile":{"path":"/etc/example","presence":1,"uid":4294967295}}`,
		`{"managedFile":{"path":"/etc/example","presence":2,"content":""}}`,
		`{"sysctl":{"key":"net/ipv4/ip_forward","value":"0"}}`,
		`{"sysctl":{"key":"net..ipv4","value":"0"}}`,
		`{"sysctl":{"key":"net.ipv4.ip_forward","value":"0\nother=1"}}`,
		`{"sysctl":{"key":"net.ipv4.ip_forward","value":"0 #comment"}}`,
		`{"sysctl":{"key":"net.ipv4.ip_forward","value":" 0"}}`,
		`{"systemdDefinition":{"presence":1,"timer":{"unit":"lindm-update.timer","service":{"kind":1,"canonicalKey":"example.service"},"schedule":{"intervalSeconds":60}}}}`,
		`{"systemdDefinition":{"presence":1,"timer":{"unit":"example.timer","service":{"kind":1,"canonicalKey":"lindm.service"},"schedule":{"intervalSeconds":60}}}}`,
		`{"systemdDefinition":{"presence":1,"timer":{"unit":"example.timer","service":{"kind":2,"canonicalKey":"operators"},"schedule":{"intervalSeconds":60}}}}`,
		`{"systemdDefinition":{"presence":1,"timer":{"unit":"example.timer","service":{"kind":1,"canonicalKey":"example.service"},"schedule":{"daily":{"hour":24}}}}}`,
		`{"systemdDefinition":{"presence":1,"dropIn":{"unit":"lindm-executor.service","cpuWeight":100}}}`,
		`{"systemdDefinition":{"presence":1,"dropIn":{"unit":"example.service"}}}`,
		`{"systemdDefinition":{"presence":1,"dropIn":{"unit":"example.service","cpuWeight":10001}}}`,
		`{"encryptionCompliance":{}}`,
		`{"encryptionCompliance":{"requireLuksRoot":true,"requireEscrow":false}}`,
	}
	for i, document := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var desired resourcev1.ResourceDesiredState
			if err := protojson.Unmarshal([]byte(document), &desired); err != nil {
				t.Fatal(err)
			}
			if _, err := CanonicalRef(&desired); err == nil {
				t.Fatalf("invalid host shape accepted: %s", document)
			}
		})
	}
	for _, document := range []string{
		`{"systemdDefinition":{"presence":1,"dropIn":{"unit":"example.service","execStart":"/bin/sh"}}}`,
		`{"encryptionCompliance":{"requireLuksRoot":true,"encryptDevice":"/dev/sda"}}`,
	} {
		var desired resourcev1.ResourceDesiredState
		if err := protojson.Unmarshal([]byte(document), &desired); err == nil {
			t.Fatal("open native action field accepted")
		}
	}
	file := desiredJSON(t, `{"managedFile":{"path":"/etc/example","presence":1,"content":""}}`)
	file.GetManagedFile().Content = bytes.Repeat([]byte("x"), 32768)
	if err := ValidateDesired(file); err != nil {
		t.Fatalf("maximum bounded content rejected: %v", err)
	}
	file.GetManagedFile().Content = append(file.GetManagedFile().Content, 'x')
	if err := ValidateDesired(file); err == nil {
		t.Fatal("oversized file content accepted")
	}
}

func TestHostNativeClaimsConflict(t *testing.T) {
	file := claimsJSON(t, `{"managedFile":{"path":"/etc/example","presence":1,"content":"YQ=="}}`)
	other := claimsJSON(t, `{"managedFile":{"path":"/etc/example","presence":1,"content":"Yg=="}}`)
	if !Conflicts(file, other) || Conflicts(file, file) {
		t.Fatal("file claims did not distinguish native content")
	}
	live := claimsJSON(t, `{"sysctl":{"key":"net.ipv4.ip_forward","value":"0","persistent":true}}`)
	other = claimsJSON(t, `{"sysctl":{"key":"net.ipv4.ip_forward","value":"1"}}`)
	if !Conflicts(live, other) || Conflicts(live, live) {
		t.Fatal("sysctl claims did not bind live kernel value")
	}
	for _, claim := range live {
		if claim.GetDomain() != resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE {
			continue
		}
		writer := claimsJSON(t, fmt.Sprintf(`{"managedFile":{"path":%q,"presence":1,"content":""}}`, claim.GetKey()))
		if !Conflicts(live, writer) {
			t.Fatal("sysctl persistence escaped file ownership conflict")
		}
	}
	dropIn := claimsJSON(t, `{"systemdDefinition":{"presence":1,"dropIn":{"unit":"example.service","cpuWeight":100}}}`)
	writer := claimsJSON(t, `{"managedFile":{"path":"/etc/systemd/system/example.service.d/60-lindm.conf","presence":1,"content":""}}`)
	if !Conflicts(dropIn, writer) {
		t.Fatal("native definition file escaped cross-kind ownership conflict")
	}
	encryption := claimsJSON(t, `{"encryptionCompliance":{"requireLuksRoot":true,"requireEscrow":true,"requireTpm":true}}`)
	if len(encryption) != 3 || Conflicts(encryption, encryption) {
		t.Fatal("encryption requirements did not yield compatible independent claims")
	}
	for _, claim := range encryption {
		if claim.GetDomain() != resourcev1.ClaimDomain_CLAIM_DOMAIN_ENCRYPTION_COMPLIANCE || claim.GetMode() != resourcev1.ClaimMode_CLAIM_MODE_REQUIRED {
			t.Fatal("compliance acquired a mutation claim")
		}
	}
}

func TestHostPlansBindBeforeAndReleaseInverse(t *testing.T) {
	cases := []struct {
		desired  string
		observed string
	}{
		{`{"managedFile":{"path":"/etc/example","presence":1,"content":""}}`, `{"managedFile":{"path":"/etc/example","ancestrySha256":"` + fixtureDigest + `"}}`},
		{`{"sysctl":{"key":"net.ipv4.ip_forward","value":"0"}}`, `{"sysctl":{"key":"net.ipv4.ip_forward","value":"1","persistenceGraphSha256":"` + fixtureDigest + `","nativeIdentitySha256":"` + fixtureDigest + `","persistenceFileState":{"path":"/etc/sysctl.d/example.conf","ancestrySha256":"` + fixtureDigest + `"}}}`},
		{`{"systemdDefinition":{"presence":1,"dropIn":{"unit":"example.service","cpuWeight":100}}}`, `{"systemdDefinition":{"canonicalKey":"drop-in/example.service","definitionSha256":"` + fixtureDigest + `","targetDefinitionSha256":"` + fixtureDigest + `","timerScheduleSha256":"` + fixtureDigest + `","fileState":{"path":"/etc/systemd/system/example.service.d/50-lindm.conf","ancestrySha256":"` + fixtureDigest + `"},"effectiveOptions":{}}}`},
		{`{"encryptionCompliance":{"requireLuksRoot":true}}`, `{"encryptionCompliance":{"evidenceSha256":"` + fixtureDigest + `"}}`},
	}
	for _, test := range cases {
		desired := desiredJSON(t, test.desired)
		t.Run(desired.GetRef().GetKind().String(), func(t *testing.T) {
			_, template, plan := serviceEvidence(t)
			var before resourcev1.ResourceObservation
			if err := protojson.Unmarshal([]byte(test.observed), &before); err != nil {
				t.Fatal(err)
			}
			before.Ref, before.Metadata = desired.GetRef(), template.GetMetadata()
			desiredDigest, err := DesiredDigest(desired)
			if err != nil {
				t.Fatal(err)
			}
			beforeDigest, err := ObservationDigest(&before)
			if err != nil {
				t.Fatal(err)
			}
			plan.Ref, plan.Before = desired.GetRef(), &before
			plan.DesiredSha256, plan.ObservationSha256 = desiredDigest[:], beforeDigest[:]
			message := plan.ProtoReflect()
			field := message.Descriptor().Fields().ByNumber(protoreflect.FieldNumber(desired.GetRef().GetKind()) + 9)
			native := message.NewField(field).Message()
			desiredMessage := desired.ProtoReflect()
			native.Set(native.Descriptor().Fields().ByName("desired"), desiredMessage.Get(desiredMessage.WhichOneof(desiredMessage.Descriptor().Oneofs().ByName("state"))))
			beforeMessage := before.ProtoReflect()
			native.Set(native.Descriptor().Fields().ByName("before"), beforeMessage.Get(beforeMessage.WhichOneof(beforeMessage.Descriptor().Oneofs().ByName("observed"))))
			native.Set(native.Descriptor().Fields().ByName("change"), protoreflect.ValueOfEnum(5))
			if candidate := native.Descriptor().Fields().ByName("rendered_candidate_sha256"); candidate != nil {
				native.Set(candidate, protoreflect.ValueOfBytes(make([]byte, 32)))
			}
			message.Set(field, protoreflect.ValueOfMessage(native))
			if _, err := PlanDigest(plan); err != nil {
				t.Fatal(err)
			}
			plan.ObservationSha256[0] ^= 1
			if err := ValidatePlan(plan); err == nil {
				t.Fatal("substituted observation digest accepted")
			}
			plan.ObservationSha256[0] ^= 1
			plan.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
			if desired.GetEncryptionCompliance() != nil {
				if err := ValidatePlan(plan); err != nil {
					t.Fatalf("read-only compliance release rejected: %v", err)
				}
				native.Set(native.Descriptor().Fields().ByName("change"), protoreflect.ValueOfEnum(4))
				if err := ValidatePlan(plan); err == nil {
					t.Fatal("compliance release acquired mutation authority")
				}
				return
			}
			if err := ValidatePlan(plan); err == nil {
				t.Fatal("unbound release accepted")
			}
			inverse := &resourcev1.OwnershipInverseBinding{LedgerRevisionSha256: make([]byte, 32), LastAppliedSha256: make([]byte, 32), NativeIdentitySha256: make([]byte, 32), InverseSha256: make([]byte, 32)}
			native.Set(native.Descriptor().Fields().ByName("inverse"), protoreflect.ValueOfMessage(inverse.ProtoReflect()))
			if err := ValidatePlan(plan); err != nil {
				t.Fatal(err)
			}
			inverse.LedgerRevisionSha256[0] = 1
			if err := ValidatePlan(plan); err == nil {
				t.Fatal("different ownership revision accepted")
			}
		})
	}
}

func TestEncryptionConvergenceNeedsPositiveRootEvidence(t *testing.T) {
	_, observation, _ := serviceEvidence(t)
	observation.Ref = &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE, CanonicalKey: "system/root"}
	observation.Observed = &resourcev1.ResourceObservation_EncryptionCompliance{EncryptionCompliance: &resourcev1.EncryptionComplianceObservation{EvidenceSha256: make([]byte, 32)}}
	verification := &resourcev1.ResourceVerification{Ref: observation.GetRef(), DesiredSha256: make([]byte, 32), PlanSha256: make([]byte, 32), After: observation, Disposition: resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED,
		Checks: &resourcev1.ResourceVerification_EncryptionCompliance{EncryptionCompliance: &resourcev1.EncryptionComplianceChecks{LuksRootRequirementMet: true, EscrowRequirementMet: true, TpmRequirementMet: true, EvidenceComplete: true, Converged: true}}}
	if err := ValidateVerification(verification); err == nil {
		t.Fatal("missing root evidence became converged")
	}
	observation.GetEncryptionCompliance().LuksRoot = proto.Bool(true)
	observation.GetEncryptionCompliance().RootLuksUuid = proto.String(fixtureID)
	observation.GetEncryptionCompliance().RootIdentityBasis = resourcev1.RootStorageIdentityBasis_ROOT_STORAGE_IDENTITY_BASIS_WWN_SERIAL
	observation.GetEncryptionCompliance().RootWwn = "0x5000c500fixture01"
	observation.GetEncryptionCompliance().RootSerial = "fixture-root-serial"
	observation.GetEncryptionCompliance().RootSizeBytes = 64 << 30
	if err := ValidateVerification(verification); err != nil {
		t.Fatal(err)
	}
	observation.Metadata.ObservationStatus = resourcev1.ObservationStatus_OBSERVATION_STATUS_UNAVAILABLE
	if err := ValidateVerification(verification); err == nil {
		t.Fatal("unavailable root evidence became converged")
	}
}

func TestHostSchemaRejectsOversizedAndUnknownInputs(t *testing.T) {
	file := desiredJSON(t, `{"managedFile":{"path":"/etc/example","presence":1,"mode":0}}`)
	file.GetManagedFile().ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01})
	if err := ValidateDesired(file); err == nil {
		t.Fatal("unknown nested file field accepted")
	}
	for _, document := range []string{
		fmt.Sprintf(`{"sysctl":{"key":"net.ipv4.ip_forward","value":%q}}`, strings.Repeat("1", 4097)),
		fmt.Sprintf(`{"sysctl":{"key":%q,"value":"0"}}`, strings.Repeat("a", 256)+".key"),
	} {
		var desired resourcev1.ResourceDesiredState
		if err := protojson.Unmarshal([]byte(document), &desired); err != nil {
			t.Fatal(err)
		}
		if _, err := CanonicalRef(&desired); err == nil {
			t.Fatal("oversized sysctl key/value accepted")
		}
	}
	// Proto JSON bytes decoding preserves the declared public content.
	content := base64.StdEncoding.EncodeToString([]byte("public banner"))
	desired := desiredJSON(t, fmt.Sprintf(`{"managedFile":{"path":"/etc/example","presence":1,"content":%q}}`, content))
	if string(desired.GetManagedFile().GetContent()) != "public banner" {
		t.Fatal("public content changed")
	}
}

func TestHostChecksRejectPartialConvergence(t *testing.T) {
	rules, err := validator()
	if err != nil {
		t.Fatal(err)
	}
	cases := []proto.Message{
		&resourcev1.ManagedFileChecks{PresenceMatches: true, ContentMatches: true, ModeMatches: true, OwnerMatches: true, AncestrySafe: true, Converged: true},
		&resourcev1.SysctlChecks{LiveValueMatches: true, PersistenceMatches: true, PersistenceOwnerMatches: true, Converged: true},
		&resourcev1.SystemdDefinitionChecks{DefinitionMatches: true, EffectiveOptionsMatch: true, TargetServiceExists: true, TimerStateMatches: true, DaemonReloadCompleted: true, Converged: true},
		&resourcev1.EncryptionComplianceChecks{LuksRootRequirementMet: true, EscrowRequirementMet: true, TpmRequirementMet: true, EvidenceComplete: true, Converged: true},
	}
	for _, checks := range cases {
		t.Run(string(checks.ProtoReflect().Descriptor().Name()), func(t *testing.T) {
			if err := rules.Validate(checks); err != nil {
				t.Fatal(err)
			}
			fields := checks.ProtoReflect().Descriptor().Fields()
			for i := range fields.Len() {
				field := fields.Get(i)
				// Cross-boot persistence evidence is informational, not an apply prerequisite.
				if field.Name() == "converged" || field.Name() == "reboot_persistence_verified" {
					continue
				}
				checks.ProtoReflect().Set(field, protoreflect.ValueOfBool(false))
				if err := rules.Validate(checks); err == nil {
					t.Errorf("converged with failed %s", field.Name())
				}
				checks.ProtoReflect().Set(field, protoreflect.ValueOfBool(true))
			}
		})
	}
}

func TestPlanRejectsSubstitutedTypedBefore(t *testing.T) {
	_, _, plan := serviceEvidence(t)
	plan.GetSystemdService().Before = proto.CloneOf(plan.GetSystemdService().GetBefore())
	plan.GetSystemdService().Before.ActiveState = "inactive"
	if err := ValidatePlan(plan); err == nil {
		t.Fatal("typed native before differed from signed envelope observation")
	}
}

func TestNativePlatformMissingVersionIsNotSynthesized(t *testing.T) {
	_, observation, _ := serviceEvidence(t)
	product := observation.GetMetadata().GetBackend().GetProduct()
	product.OsId, product.Product, product.Version = "arch", "Arch Linux", ""
	if err := ValidateObservation(observation); err != nil {
		t.Fatal(err)
	}
	if product.GetVersion() != "" {
		t.Fatal("missing native version was synthesized")
	}
}
