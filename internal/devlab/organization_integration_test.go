//go:build integration

package devlab_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	"lindm/internal/ctl"
	"lindm/internal/devlab"
	"lindm/internal/loadlab"
	"lindm/internal/orgapply"
)

// lindmd rejects search_path overrides, so (like the native approval tests) this
// uses devlab's disposable database rather than a testdb schema. All organization
// mutations and authentication flow through the actual TLS product endpoints.
func TestOrganizationApplyRealServer(t *testing.T) {
	binary, repository := os.Getenv("LINDM_NATIVE_SERVER_BINARY"), os.Getenv("LINDM_NATIVE_REPOSITORY")
	if binary == "" || repository == "" {
		t.Fatal("native-server integration requires LINDM_NATIVE_SERVER_BINARY and LINDM_NATIVE_REPOSITORY")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	fixture, err := devlab.OpenLocalConsoleAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	}()
	// Exercise real enrollment/inventory before the full declaration's rollout
	// captures a cohort. These are synthetic protocol devices, not native proof.
	population, err := loadlab.Populate(ctx, fixture, loadlab.PopulateOptions{Devices: 4, Packages: 1, AssignmentPercent: 1, EnrollmentWorkers: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Read from the tested checkout, not the shared fixture repository (which may
	// be at a different commit during a private-worktree integration gate).
	specPath := filepath.Join("..", "..", "lab", "demo", "org.json")
	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := orgapply.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(context.WithoutCancel(ctx)); err != nil {
			t.Error(err)
		}
	}()
	for index, label := range []string{"department/engineering", "department/finance", "department/it-helpdesk", "department/contractors"} {
		if _, err := owner.Admin.SetDeviceMetadata(ctx, connect.NewRequest(&adminv1.SetDeviceMetadataRequest{
			RequestId: uuid.NewString(), DeviceId: population.DeviceIDs[index],
			Metadata: &adminv1.DeviceMetadata{Labels: []string{label}},
			Reason:   "qualify unchanged demo organization against real enrolled inventory cohorts",
		})); err != nil {
			t.Fatal(err)
		}
	}
	// Authorization and accounts use the same browser-only reviewed-plan route
	// as the console, rather than rewriting the server's bootstrap config.
	preview, err := owner.ApplyOrganization(ctx, &orgv1.ApplyOrganizationRequest{Organization: spec})
	if err != nil {
		t.Fatal(err)
	}
	first, err := owner.ApplyOrganization(ctx, &orgv1.ApplyOrganizationRequest{Organization: spec, Apply: true, ExpectedPlanSha256: preview.GetPlanSha256()})
	if err != nil {
		t.Fatal(err)
	}
	defer clearOrganizationSecrets(first)
	if first.GetFailureCode() != "" || len(first.GetSecrets()) != len(spec.GetProvisioningTokens())+len(spec.GetGrants())+len(spec.GetAccounts())-1 {
		t.Fatalf("unexpected first apply: failure %q (%s), %d secrets, outcomes %+v", first.GetFailureCode(), first.GetFailureReason(), len(first.GetSecrets()), first.GetOutcomes())
	}
	state, err := owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !state.Msg.GetAuthorization().GetRuntime() || !proto.Equal(state.Msg.GetAuthorization().GetPolicy(), spec.GetAuthorization()) {
		t.Fatal("organization authorization did not become runtime authority")
	}
	secondPreview, err := owner.ApplyOrganization(ctx, &orgv1.ApplyOrganizationRequest{Organization: spec})
	if err != nil {
		t.Fatal(err)
	}
	second, err := owner.ApplyOrganization(ctx, &orgv1.ApplyOrganizationRequest{Organization: spec, Apply: true, ExpectedPlanSha256: secondPreview.GetPlanSha256()})
	if err != nil {
		t.Fatal(err)
	}
	defer clearOrganizationSecrets(second)
	if second.GetFailureCode() != "" || len(second.GetSecrets()) != 0 {
		t.Fatal("second apply failed or reissued secrets")
	}
	for _, o := range second.Outcomes {
		switch o.Kind {
		case "advisory_exception":
			if o.Status != "pending" {
				t.Fatalf("exception without findings: %+v", o)
			}
		default:
			if o.Status != "unchanged" {
				t.Fatalf("second apply drift: %+v", o)
			}
		}
	}
	// Independent issuance with the same live product name must not create a
	// duplicate, even when the client raced its prior list snapshot.
	duplicate := spec.GetGrants()[0].GetRequest()
	_, err = owner.Admin.CreateEnrollmentGrant(ctx, connect.NewRequest(&adminv1.CreateEnrollmentGrantRequest{RequestId: uuid.NewString(), Name: spec.GetName() + "/" + spec.GetGrants()[0].GetName(), LifetimeSeconds: duplicate.GetLifetimeSeconds(), Reason: "exercise named grant uniqueness"}))
	if connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("duplicate grant name: %v", err)
	}

	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "cli.json")
	ca, err := os.ReadFile(filepath.Join(devlab.FixturePath(repository), "transport-ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	cli, err := ctl.New(configPath, &authv1.CLIConfig{ServerOrigin: fixture.ConsoleOrigin, CaPem: string(ca)})
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Login(ctx, owner.ApproveCLI); err != nil {
		t.Fatal(err)
	}
	if err := cli.Close(); err != nil {
		t.Fatal(err)
	}
	for _, dry := range []bool{true, false} {
		args := []string{"apply", "-config", configPath, "-f", specPath, "-o", "json"}
		if dry {
			args = append(args, "-dry-run")
		}
		var output bytes.Buffer
		if err := ctl.Run(ctx, args, &output, nil); err != nil {
			t.Fatal(err)
		}
		var result struct {
			Outcomes []orgapply.Outcome `json:"outcomes"`
		}
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		for _, secret := range first.GetSecrets() {
			if strings.Contains(output.String(), secret.GetSecret()) {
				t.Fatal("CLI output exposed a secret")
			}
		}
		for _, o := range result.Outcomes {
			if o.Kind == "account" && o.Status != "pending" {
				t.Fatal("CLI bearer claimed browser account authority")
			}
		}
	}
	var output bytes.Buffer
	if err := ctl.Run(ctx, []string{"logout", "-config", configPath}, &output, nil); err != nil {
		t.Fatal(err)
	}
}

func clearOrganizationSecrets(response *orgv1.ApplyOrganizationResponse) {
	for _, secret := range response.GetSecrets() {
		secret.Secret = ""
	}
	response.Secrets = nil
}
