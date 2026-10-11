package platform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// nonDistroLiterals are uses of a registry ID string that do not name a
// distribution; each needs a reason.
var nonDistroLiterals = map[string]map[string]string{
	"internal/advisory/feed/osv.go": {"arch": "OSV package-URL qualifier key"},
}

// pendingMigration lists files still converting to the registry. It only
// shrinks: a listed file that no longer holds a literal fails the test until
// it is removed here, and the list is deleted when empty.
var pendingMigration = []string{
	"cmd/lab/hosts.go",
	"cmd/lab/images_redhat.go",
	"cmd/lab/lifecycle.go",
	"cmd/lab/packages.go",
	"internal/advisory/feed/arch.go",
	"internal/advisory/feed/debian_tracker.go",
	"internal/advisory/feed/feed.go",
	"internal/advisory/feed/osv_archive.go",
	"internal/advisory/feed/osv.go",
	"internal/advisory/feed/redhat.go",
	"internal/advisory/feed/rpm.go",
	"internal/advisory/feed/signed.go",
	"internal/advisory/feed/suse.go",
	"internal/advisory/match.go",
	"internal/agent/accountprovider/observe_linux.go",
	"internal/agent/accountprovider/prefix_linux.go",
	"internal/agent/definitionprovider/provider_linux.go",
	"internal/agent/dnf/versionlock.go",
	"internal/agent/firewallprovider/provider_linux.go",
	"internal/agent/inventory/inventory_linux.go",
	"internal/agent/inventory/packages_linux.go",
	"internal/agent/nativehelper/resource_linux.go",
	"internal/agent/packageprovider/dnf4_linux.go",
	"internal/agent/packageprovider/pin_linux.go",
	"internal/agent/packageprovider/provider_linux.go",
	"internal/agent/passwordprovider/native_linux.go",
	"internal/agent/passwordprovider/version_linux.go",
	"internal/agent/sysctlprovider/context_linux.go",
	"internal/agent/update/native_linux.go",
	"internal/devlab/acceptance_fixture.go",
	"internal/labhost/baseline.go",
	"internal/loadlab/inventory.go",
	"internal/packaging/arch_publish.go",
	"internal/packaging/arch_rejection.go",
	"internal/packaging/result.go",
	"internal/vmlab/acceptance_linux.go",
	"internal/vmlab/debian_golden_linux.go",
	"internal/vmlab/encrypted_golden_linux.go",
	"internal/vmlab/encrypted_installer_linux.go",
	"internal/vmlab/encrypted_storage_inspect_linux.go",
	"internal/vmlab/installed_image_linux.go",
	"internal/vmlab/inventory_unavailable_linux.go",
	"internal/vmlab/tumbleweed_installer_linux.go",
	"internal/vmlab/vm_airgap_linux.go",
	"internal/vmlab/vm_arch_linux.go",
	"internal/vmlab/vm_assistance_guest_linux.go",
	"internal/vmlab/vm_assistance_linux.go",
	"internal/vmlab/vm_device_actions_boot_fixture_linux.go",
	"internal/vmlab/vm_device_actions_linux.go",
	"internal/vmlab/vm_device_actions_setup_linux.go",
	"internal/vmlab/vm_dispatch_linux.go",
	"internal/vmlab/vm_distribution_linux.go",
	"internal/vmlab/vm_inspect_linux.go",
	"internal/vmlab/vm_redhat_linux.go",
	"internal/vmlab/vm_resource_firewall_coexistence_linux.go",
	"internal/vmlab/vm_resources_linux.go",
	"internal/vmlab/vm_server_linux.go",
	"internal/vmlab/vm_services_linux.go",
	"internal/vmlab/vm_unattended_linux.go",
	"internal/vmlab/vm_update_packages_linux.go",
	"internal/vmlab/vm_updates_linux.go",
}

// TestNoDistroIDLiteralsOutsideRegistry keeps distribution knowledge in the
// registry: product and lab code ask it for capabilities and native facts
// instead of comparing os-release IDs. Tests may still construct observed
// os-release fixtures.
func TestNoDistroIDLiteralsOutsideRegistry(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			if d.IsDir() {
				if rel == filepath.Join("internal", "platform") || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			if ast.IsGenerated(file) {
				return nil
			}
			skip := map[*ast.BasicLit]bool{}
			ast.Inspect(file, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.ImportSpec:
					skip[n.Path] = true
				case *ast.Field:
					if n.Tag != nil {
						skip[n.Tag] = true
					}
				case *ast.BasicLit:
					if n.Kind != token.STRING || skip[n] {
						return true
					}
					value, err := strconv.Unquote(n.Value)
					if err == nil && KnownID(value) && nonDistroLiterals[filepath.ToSlash(rel)][value] == "" {
						found = append(found, filepath.ToSlash(rel)+": "+value)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(found)
	found = slices.Compact(found)
	for _, f := range found {
		file, _, _ := strings.Cut(f, ": ")
		if !slices.Contains(pendingMigration, file) {
			t.Errorf("distribution ID literal outside internal/platform: %s", f)
		}
	}
	for _, file := range pendingMigration {
		if !slices.ContainsFunc(found, func(f string) bool { return strings.HasPrefix(f, file+": ") }) {
			t.Errorf("%s is migrated; remove it from pendingMigration", file)
		}
	}
}
