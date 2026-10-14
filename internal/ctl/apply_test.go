// SPDX-License-Identifier: Apache-2.0

package ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
	orgv1 "lindm/gen/lindm/org/v1"
	"lindm/internal/orgapply"
)

func applyDocument(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "org.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyDryRunAndStrictInput(t *testing.T) {
	for _, tc := range []struct {
		name, document string
		valid          bool
	}{
		{"valid", `{"name":"demo","accounts":[{"username":"owner","role":"owner"}]}`, true},
		{"unknown", `{"name":"demo","typo":"private-value"}`, false},
		{"nested unknown", `{"name":"demo","accounts":[{"username":"owner","role":"owner","password":"private-value"}]}`, false},
		{"invalid", `{"name":""}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			planned := false
			engine := applyEngine{
				plan: func(_ context.Context, _ adminv1connect.AdminServiceClient, spec *orgv1.Organization) (*orgapply.ChangePlan, error) {
					planned = true
					if spec.GetName() != "demo" {
						t.Fatal("lost organization")
					}
					return &orgapply.ChangePlan{Outcomes: []orgapply.Outcome{{Kind: "account", Name: "owner", Status: "pending", Detail: "requires console session"}, {Kind: "authorization", Status: "updated", Detail: "replace runtime authorization"}}}, nil
				},
				apply: func(context.Context, adminv1connect.AdminServiceClient, *orgapply.ChangePlan, orgapply.Options) (*orgapply.Result, error) {
					t.Fatal("dry-run mutated")
					return nil, nil
				},
			}
			var out bytes.Buffer
			f := commandFlags{file: applyDocument(t, tc.document), dryRun: true}
			err := f.applyOrganization(t.Context(), nil, &out, "json", engine)
			if (err == nil) != tc.valid || planned != tc.valid {
				t.Fatalf("valid=%v planned=%v err=%v", tc.valid, planned, err)
			}
			if err != nil && strings.Contains(err.Error(), "private-value") {
				t.Fatal("decoder leaked input")
			}
			if tc.valid && (!strings.Contains(out.String(), "requires console session") || !strings.Contains(out.String(), "replace runtime authorization")) {
				t.Fatal("missing authority boundaries")
			}
		})
	}
}

func TestApplySecretsPrivateAndPartialFailure(t *testing.T) {
	for _, format := range []string{"table", "json"} {
		for _, fail := range []bool{false, true} {
			t.Run(format+map[bool]string{false: " success", true: " partial"}[fail], func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "secrets.json")
				calls := 0
				failure := errors.New("later object failed")
				engine := applyEngine{
					plan: func(context.Context, adminv1connect.AdminServiceClient, *orgv1.Organization) (*orgapply.ChangePlan, error) {
						return &orgapply.ChangePlan{Outcomes: []orgapply.Outcome{{Kind: "enrollment_grant", Status: "created"}}}, nil
					},
					apply: func(_ context.Context, _ adminv1connect.AdminServiceClient, _ *orgapply.ChangePlan, options orgapply.Options) (*orgapply.Result, error) {
						calls++
						if options.AccountClient != nil {
							t.Fatal("CLI gained browser account authority")
						}
						info, err := os.Stat(path)
						if err != nil || info.Mode().Perm() != 0o600 {
							t.Fatalf("output not reserved privately before mutation: %v", err)
						}
						result := &orgapply.Result{Outcomes: []orgapply.Outcome{{Kind: "enrollment_grant", Name: "new\nrow\x1b[31m", Status: "created", Detail: "issued"}}, Secrets: []orgapply.Secret{{Kind: "enrollment_grant", Name: "grant", Value: "issued-secret"}}}
						if fail {
							return result, failure
						}
						return result, nil
					},
				}
				f := commandFlags{file: applyDocument(t, `{"name":"demo"}`), secretsOut: path}
				var out bytes.Buffer
				err := f.applyOrganization(t.Context(), nil, &out, format, engine)
				if errors.Is(err, failure) != fail || (!fail && err != nil) {
					t.Fatalf("unexpected error: %v", err)
				}
				if calls != 1 {
					t.Fatalf("mutation calls=%d", calls)
				}
				if strings.Contains(out.String(), "issued-secret") || strings.ContainsAny(out.String(), "\x1b") {
					t.Fatal("unsafe output")
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var secrets []orgapply.Secret
				if err := json.Unmarshal(data, &secrets); err != nil {
					t.Fatal(err)
				}
				if len(secrets) != 1 || secrets[0].Value != "issued-secret" {
					t.Fatal("issued secret lost")
				}
			})
		}
	}
}

func TestApplyRefusesUnsafeSecretDestinations(t *testing.T) {
	for _, mode := range []string{"missing", "existing", "symlink", "dry-run"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			existing := filepath.Join(dir, "existing")
			if err := os.WriteFile(existing, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			f := commandFlags{file: applyDocument(t, `{"name":"demo"}`)}
			switch mode {
			case "existing":
				f.secretsOut = existing
			case "symlink":
				f.secretsOut = filepath.Join(dir, "link")
				if err := os.Symlink(existing, f.secretsOut); err != nil {
					t.Fatal(err)
				}
			case "dry-run":
				f.secretsOut = filepath.Join(dir, "new")
				f.dryRun = true
			}
			engine := applyEngine{
				plan: func(context.Context, adminv1connect.AdminServiceClient, *orgv1.Organization) (*orgapply.ChangePlan, error) {
					return &orgapply.ChangePlan{Outcomes: []orgapply.Outcome{{Kind: "provisioning_token", Status: "created"}}}, nil
				},
				apply: func(context.Context, adminv1connect.AdminServiceClient, *orgapply.ChangePlan, orgapply.Options) (*orgapply.Result, error) {
					t.Fatal("mutated without safe destination")
					return nil, nil
				},
			}
			var out bytes.Buffer
			if err := f.applyOrganization(t.Context(), nil, &out, "table", engine); err == nil {
				t.Fatal("unsafe output accepted")
			}
			data, err := os.ReadFile(existing)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "preserve" {
				t.Fatal("overwrote existing output")
			}
		})
	}
}

func TestApplyFlags(t *testing.T) {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	var f commandFlags
	if err := f.register(flags, "apply"); err != nil {
		t.Fatal(err)
	}
	if err := flags.Parse([]string{"-f", "org.json", "-dry-run"}); err != nil {
		t.Fatal(err)
	}
	if f.file != "org.json" || !f.dryRun || f.mutation {
		t.Fatal("apply flag contract changed")
	}
}
