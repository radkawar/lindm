package resource

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestSSHBannerSchemaPreservesPublicText(t *testing.T) {
	for _, text := range []string{"Authorized use only.\n", "日本語のログイン通知\n", "Literal text: Banner /somewhere\nMatch User nobody\n"} {
		desired := &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER, CanonicalKey: "system"}, State: &resourcev1.ResourceDesiredState_SshServer{SshServer: &resourcev1.SSHServerDesired{BannerText: proto.String(text)}}}
		if err := ValidateDesired(desired); err != nil {
			t.Fatal(err)
		}
		if !SSHBannerOnly(desired.GetSshServer()) || desired.GetSshServer().GetBannerText() != text {
			t.Fatal("public notice changed")
		}
	}
	for _, text := range []string{"", "bad\x00text", "bad\x1b[31m", strings.Repeat("a", 8193), strings.Repeat("あ", 2731)} {
		desired := &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER, CanonicalKey: "system"}, State: &resourcev1.ResourceDesiredState_SshServer{SshServer: &resourcev1.SSHServerDesired{BannerText: proto.String(text)}}}
		if err := ValidateDesired(desired); err == nil {
			t.Fatalf("invalid banner accepted (%d bytes)", len(text))
		}
	}
}

func TestSSHBannerClaimsProtectNativeFiles(t *testing.T) {
	desired := desiredJSON(t, `{"sshServer":{"bannerText":"Authorized use only.\n"}}`)
	claims, err := Claims(desired)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{SSHBannerPath, SSHBannerDirectivePath} {
		found := false
		for _, claim := range claims {
			if claim.GetDomain() == resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE && claim.GetKey() == path {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing collision claim for %s", path)
		}
	}
}
