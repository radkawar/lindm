// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestScaleOutOptionsRejectUnsafeTopology(t *testing.T) {
	valid := ScaleOutOptions{SSHHost: "spark2", RemoteBinary: "/opt/lindm/lindmd", RemoteAddress: "192.0.2.2", RemoteCPUs: "2-4,8", Replicas: 2}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ScaleOutOptions){
		func(o *ScaleOutOptions) { o.SSHHost = "-oProxyCommand=evil" },
		func(o *ScaleOutOptions) { o.SSHHost = "spark2 other" },
		func(o *ScaleOutOptions) { o.RemoteBinary = "lindmd" },
		func(o *ScaleOutOptions) { o.RemoteAddress = "0.0.0.0" },
		func(o *ScaleOutOptions) { o.RemoteAddress = "127.0.0.1" },
		func(o *ScaleOutOptions) { o.RemoteAddress = "spark2" },
		func(o *ScaleOutOptions) { o.RemoteAddress = "224.0.0.1" },
		func(o *ScaleOutOptions) { o.RemoteAddress = "169.254.010.49" },
		func(o *ScaleOutOptions) { o.Replicas = 4 },
		func(o *ScaleOutOptions) { o.RemoteCPUs = "1;echo" },
		func(o *ScaleOutOptions) { o.LocalReplicaCPUs = "4-5" },
	} {
		options := valid
		change(&options)
		if err := options.validate(); err == nil {
			t.Fatalf("accepted unsafe topology: %+v", options)
		}
	}
	valid.Replicas, valid.LocalReplicaCPUs = 3, "4-5"
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	valid.RemoteAddress = "169.254.10.49" // DGX direct link
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestScaleOutRejectsUnownedDatabaseBeforeSideEffects(t *testing.T) {
	options := ScaleOutOptions{SSHHost: "spark2", RemoteBinary: "/opt/lindm/lindmd", RemoteAddress: "192.0.2.2"}
	fixture := &AuthorityFixture{directory: t.TempDir()}
	if err := fixture.ConfigureScaleOut(context.Background(), options); err == nil {
		t.Fatal("accepted an unowned database fixture")
	}
	if fixture.scaleOut != nil || fixture.closed {
		t.Fatal("invalid scale-out mutated fixture ownership")
	}
	if _, err := fixture.MeasureScaleOut(context.Background()); err == nil {
		t.Fatal("reported fabricated replica metrics")
	}
}

func TestScaleOutStagesOnlyRuntimeCustodyAndPreservesAuthority(t *testing.T) {
	directory := t.TempDir()
	contents := map[string]string{
		"server.crt": "transport leaf", "server.key": "TLS private", "device-ca.crt": "device CA", "device-ca.key": "device issuer",
		"root.json": "execution root", "bootstrap.json": "signed bootstrap", "plan.key": "plan issuer", "start.key": "start issuer",
		"transport-ca.crt": "trust roots", "transport-ca.key": "DO NOT TRANSFER offline authority", "secret": "OIDC secret",
	}
	dsn := &url.URL{Scheme: "postgresql", User: url.UserPassword("owned", "password"), Host: "192.0.2.1:32123", Path: "/owned_database"}
	dsn.RawQuery = url.Values{"sslmode": {"verify-full"}, "sslrootcert": {filepath.Join(directory, "transport-ca.crt")}}.Encode()
	contents["database-url"] = dsn.String()
	for name, data := range contents {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &configv1.ServerConfig{
		DeploymentId: "owned-deployment", PublicUrl: "https://localhost:18444", DevicePublicUrl: proto.String("https://localhost:18445"),
		AdminListener: &configv1.ListenerConfig{Address: "192.0.2.2", Port: 40001}, DeviceListener: &configv1.ListenerConfig{Address: "192.0.2.2", Port: 40002},
		Database:           &configv1.DatabaseConfig{UrlFile: "database-url", MigrationUrlFile: proto.String("database-url"), MaxConnections: 32, AdminConnections: proto.Uint32(2)},
		Tls:                &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
		DeviceCa:           &configv1.DeviceCAConfig{CertificateFile: "device-ca.crt", PrivateKeyFile: "device-ca.key"},
		TrustedCaFile:      "transport-ca.crt",
		Authentication:     &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Keycloak{Keycloak: &configv1.KeycloakDirectory{Issuer: "https://localhost:18443/realms/lindm", ClientSecretFile: "secret", DirectoryClientSecretFile: "secret"}}},
		ExecutionBootstrap: &configv1.ExecutionBootstrapConfig{RootFile: "root.json", BootstrapFile: "bootstrap.json"},
		ExecutionSigning:   &configv1.ExecutionSigningConfig{PlanKeyFile: "plan.key", StartKeyFile: "start.key"},
		Advisories:         &configv1.AdvisoryConfig{RefreshEnabled: true},
	}
	remote := "/tmp/lindm-scaleout-test"
	files, err := scaleOutFiles(cfg, directory, remote)
	if err != nil {
		t.Fatal(err)
	}
	var staged configv1.ServerConfig
	if err := protojson.Unmarshal(files["server.json"], &staged); err != nil {
		t.Fatal(err)
	}
	if staged.PublicUrl != "https://localhost:18444" || staged.Database.MaxConnections != 32 || !staged.Advisories.RefreshEnabled || staged.Authentication.GetKeycloak().Issuer != "https://localhost:18443/realms/lindm" {
		t.Fatal("replica changed shared authority, pool or leader-job configuration")
	}
	for _, data := range files {
		if strings.Contains(string(data), "DO NOT TRANSFER") || strings.Contains(string(data), directory) {
			t.Fatal("transferred offline key or left a local custody reference")
		}
	}
	for path, expected := range map[string]string{
		staged.Tls.PrivateKeyFile: "TLS private", staged.DeviceCa.PrivateKeyFile: "device issuer",
		staged.ExecutionSigning.PlanKeyFile: "plan issuer", staged.ExecutionSigning.StartKeyFile: "start issuer",
	} {
		if string(files[filepath.Base(path)]) != expected {
			t.Fatal("replica key material differs from local authority")
		}
	}
	remoteDSN, err := url.Parse(string(files[filepath.Base(staged.Database.UrlFile)]))
	if err != nil {
		t.Fatal(err)
	}
	if remoteDSN.Host != dsn.Host || remoteDSN.Path != dsn.Path || remoteDSN.User.String() != dsn.User.String() || remoteDSN.Query().Get("sslmode") != "verify-full" || !strings.HasPrefix(remoteDSN.Query().Get("sslrootcert"), remote+"/") {
		t.Fatal("remote database endpoint or TLS identity changed")
	}
	if staged.Database.UrlFile != staged.Database.GetMigrationUrlFile() {
		t.Fatal("duplicate source credential acquired inconsistent custody")
	}
}

func TestScaleOutConnectionCountersPreserveBackendIdentity(t *testing.T) {
	data := "# pxname,svname,scur,stot,status,\nadmin,FRONTEND,0,99,OPEN,\nadmin,replica1,2,11,UP,\ndevice,replica1,1,21,UP,\nadmin,replica2,3,12,UP,\ndevice,replica2,4,22,UP,\ndevice,BACKEND,5,43,UP,\n"
	counts, err := scaleOutConnectionCounts(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint64{"admin/replica1": 11, "device/replica1": 21, "admin/replica2": 12, "device/replica2": 22}
	if !reflect.DeepEqual(counts, want) {
		t.Fatalf("connection totals = %v, want %v", counts, want)
	}
	for _, invalid := range []string{"", "# pxname,svname\nadmin,replica1\n", "# pxname,svname,stot\nadmin,replica1,-1\n", "# pxname,svname,stot\nadmin,replica1,2\nadmin,replica1,3\n", "# pxname,svname,stot\nadmin,replica1\n"} {
		if _, err := scaleOutConnectionCounts(invalid); err == nil {
			t.Fatalf("accepted misleading counters %q", invalid)
		}
	}
}

func TestScaleOutProcessCountersHandleParenthesizedNames(t *testing.T) {
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[11], fields[12], fields[21] = "S", "42", "9", "123"
	ticks, rss, err := scaleOutProcessCounters("123 (lindmd worker (1)) "+strings.Join(fields, " "), 4096)
	if err != nil || ticks != 51 || rss != 123*4096 {
		t.Fatalf("process counters: ticks=%d rss=%d err=%v", ticks, rss, err)
	}
	for _, invalid := range []string{"", "1 (lindmd) S 1", "1 lindmd S 1"} {
		if _, _, err := scaleOutProcessCounters(invalid, 4096); err == nil {
			t.Fatalf("accepted malformed process counters %q", invalid)
		}
	}
}

func TestScaleOutEnvironmentDoesNotExposeMutableState(t *testing.T) {
	fixture := &AuthorityFixture{scaleOut: &scaleOutTopology{environment: ScaleOutEnvironment{Replicas: []ScaleOutReplica{{Name: "replica1", PID: 100}}}}}
	environment := fixture.ScaleOutEnvironment()
	environment.Replicas[0].PID = 200
	if fixture.ScaleOutEnvironment().Replicas[0].PID != 100 {
		t.Fatal("caller changed replica identity")
	}
	data, err := json.Marshal(environment)
	if err != nil || strings.Contains(string(data), "database-url") {
		t.Fatalf("unsafe scale-out evidence: %s, %v", data, err)
	}
	if err := fixture.Restart(context.Background()); err == nil {
		t.Fatal("restarted only one member of a configured topology")
	}
	if err := fixture.writeConfig([]byte("changed")); err == nil {
		t.Fatal("mutated only one replica configuration")
	}
}

func TestDirectPostgresRequiresOwnedDurableStorage(t *testing.T) {
	for _, storage := range []string{"", "shared", "tmpfs"} {
		if err := (LoadAuthorityOptions{DatabaseStorage: storage, PostgresListenAddress: "127.0.0.1"}).validate(); err == nil {
			t.Fatalf("exposed %q storage to remote replicas", storage)
		}
	}
	if err := (LoadAuthorityOptions{DatabaseStorage: "nvme", PostgresListenAddress: "127.0.0.1"}).validate(); err != nil {
		t.Fatal(err)
	}
}
