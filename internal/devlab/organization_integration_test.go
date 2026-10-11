//go:build integration

package devlab

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

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/ctl"
	"lindm/internal/orgapply"
)

// lindmd rejects search_path overrides, so (like the native approval tests) this
// uses devlab's disposable database rather than a testdb schema. All organization
// mutations and authentication flow through the actual TLS product endpoints.
func TestOrganizationApplyRealServer(t *testing.T) {
	binary, repository := nativeServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	fixture, err := OpenLocalConsoleAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	}()
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
	if err := fixture.ConfigureOrganizationAuthorization(ctx, spec.GetAuthorization()); err != nil {
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
	var _ orgapply.AccountClient = owner
	plan, err := orgapply.Plan(ctx, owner.Admin, spec)
	if err != nil {
		t.Fatal(err)
	}
	first, err := orgapply.Apply(ctx, owner.Admin, plan, orgapply.Options{AccountClient: owner})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Secrets) != len(spec.GetProvisioningTokens())+len(spec.GetGrants())+len(spec.GetAccounts())-1 {
		t.Fatalf("unexpected first-apply secret count %d", len(first.Secrets))
	}
	secondPlan, err := orgapply.Plan(ctx, owner.Admin, spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := orgapply.Apply(ctx, owner.Admin, secondPlan, orgapply.Options{AccountClient: owner})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Secrets) != 0 {
		t.Fatal("second apply reissued secrets")
	}
	for _, o := range second.Outcomes {
		switch o.Kind {
		case "authorization":
			if o.Status != "unsupported" {
				t.Fatalf("authorization: %+v", o)
			}
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
	ca, err := os.ReadFile(filepath.Join(FixturePath(repository), "transport-ca.crt"))
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
		for _, secret := range first.Secrets {
			if strings.Contains(output.String(), secret.Value) {
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
