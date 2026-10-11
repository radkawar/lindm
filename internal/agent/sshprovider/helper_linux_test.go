//go:build linux

package sshprovider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
)

// This is coordinator failure injection, not native sshd qualification. It
// proves that a rejected candidate cannot consume effect authority.
func TestSSHNativeSyntaxFailureNeverReachesGate(t *testing.T) {
	p := fixtureProvider()
	before := fixtureSnapshot(t, p, true)
	p.config.ObserveNative = func(context.Context) (*agentv1.ResourceOwnershipSnapshot, error) { return proto.CloneOf(before), nil }
	ledger := fixtureLedger(p, fixtureSnapshot(t, p, false), before)
	plan, target, err := p.plan(t.Context(), fixtureDesired(), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, ledger)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	p.run = func(context.Context, string, ...string) ([]byte, error) {
		calls++
		return nil, errors.New("injected sshd syntax rejection")
	}
	gate := 0
	_, err = p.applyNative(t.Context(), &agentv1.NativeResourceTransactionRequest{Plan: plan, Before: before, Target: target, Ownership: ledger}, fixtureDesired(), func(context.Context) error { gate++; return nil })
	if !errors.Is(err, ErrConflict) || gate != 0 || calls != 1 {
		t.Fatal("syntax failure consumed effect authority", err, gate, calls)
	}
}

// Real descriptor-held file transactions and rollback; command errors are
// injected rather than represented as native SSH evidence. Privilege skips do
// not qualify this boundary on a native platform.
func TestSSHFailedEffectRollsBackOnlyUntouchedInvocationFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root nativefile custody and leases")
	}
	for _, scenario := range []string{"syntax", "reload", "cancellation", "operator-edit"} {
		t.Run(scenario, func(t *testing.T) {
			dir, err := os.MkdirTemp("/var/lib", "lindm-ssh-rollback-test-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(dir); err != nil {
					t.Error(err)
				}
			})
			path := filepath.Join(dir, "notice")
			if err := os.WriteFile(path, []byte("baseline"), 0644); err != nil {
				t.Fatal(err)
			}
			p := fixtureProvider()
			template := fixtureSnapshot(t, p, true).Observation
			before, err := nativefile.Capture(path, template)
			if err != nil {
				t.Fatal(err)
			}
			target := proto.CloneOf(before)
			target.ManagedFileContent = []byte("candidate")
			target.Observation.GetManagedFile().File.Sha256 = sum(target.ManagedFileContent)
			tx, err := nativefile.Prepare(before, target)
			if err != nil {
				t.Fatal(err)
			}
			changes := bannerChanges{count: 1, files: [2]bannerChange{{tx: tx, before: before}}}
			defer func() {
				if err := changes.close(); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls, reloads := 0, 0
			p.run = func(_ context.Context, command string, _ ...string) ([]byte, error) {
				calls++
				if command == "/usr/bin/systemctl" {
					reloads++
					if reloads == 1 {
						return nil, errors.New("injected reload failure")
					}
					return nil, nil
				}
				if calls == 1 {
					switch scenario {
					case "syntax":
						return nil, errors.New("injected syntax failure")
					case "cancellation":
						cancel()
						return nil, context.Canceled
					case "operator-edit":
						if err := os.WriteFile(path, []byte("operator edit"), 0644); err != nil {
							return nil, err
						}
						return nil, errors.New("injected syntax failure")
					}
				}
				return nil, nil
			}
			plan := &resourcev1.ResourcePlan{Plan: &resourcev1.ResourcePlan_SshServer{SshServer: &resourcev1.SSHServerPlan{Reload: resourcev1.ReloadMechanism_RELOAD_MECHANISM_SYSTEMD_RELOAD}}}
			if _, err := p.commitChanges(ctx, plan, nil, &changes); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("failed effect lost UNKNOWN classification", err)
			}
			actual, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			expected := "baseline"
			if scenario == "operator-edit" {
				expected = "operator edit"
			}
			if string(actual) != expected {
				t.Fatalf("%s: rollback overwrote wrong bytes: %q", scenario, actual)
			}
			if scenario == "reload" && reloads != 2 {
				t.Fatal("restored valid baseline was not reloaded")
			}
			if scenario != "reload" && reloads != 0 {
				t.Fatal("invalid or interrupted candidate was reloaded")
			}
		})
	}
}
