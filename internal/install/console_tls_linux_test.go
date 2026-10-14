// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestBrowserCompatibleUpgradeBoundary(t *testing.T) {
	for _, cfg := range []*configv1.ServerConfig{nil, {}, {AdminTls: &configv1.TLSConfig{}}} {
		err := browserCompatibleUpgradeConfig(cfg)
		if err == nil || err.Error() != "This installation predates the browser-compatible console certificate. Install fresh and re-enroll devices." {
			t.Fatal("shared TLS upgrade did not refuse with its explicit fresh-install boundary")
		}
	}
	cfg := &configv1.ServerConfig{AdminTls: &configv1.TLSConfig{CertificateFile: "/etc/lindm/admin.crt", PrivateKeyFile: "/etc/lindm/admin.key"}, AdminCaFile: proto.String("/etc/lindm/console-ca.crt")}
	if err := browserCompatibleUpgradeConfig(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestBrowserUpgradeBoundaryRunsBeforeUpgradeAdmission(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "install_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var guard, upgrade token.Pos
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Run" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch name.Name {
			case "requireBrowserCompatibleUpgrade":
				guard = call.Pos()
			case "upgradeRelease":
				upgrade = call.Pos()
			}
			return true
		})
	}
	if guard == token.NoPos || upgrade == token.NoPos || guard >= upgrade {
		t.Fatal("shared TLS boundary is missing or executes after upgrade admission")
	}
}

func TestConsoleOriginDNSWarning(t *testing.T) {
	for _, host := range []string{"192.0.2.10", "::1", "2001:db8::1", "localhost", "console.example.test", "192.0.2.10.example.test"} {
		var output bytes.Buffer
		warnConsoleDNSRequirement(host, &output)
		want := host == "192.0.2.10" || host == "::1" || host == "2001:db8::1"
		if (output.Len() != 0) != want {
			t.Fatalf("IP-only console warning differs for %q", host)
		}
		if want && (!strings.Contains(output.String(), "DNS name") || !strings.Contains(output.String(), "WebAuthn")) {
			t.Fatal("console warning omitted the DNS/passkey remedy")
		}
	}
}
