// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestAdminDatabasePoolSizing(t *testing.T) {
	dir := databaseFixture(t)
	writeCertificate(t, dir, "root", true, nil, nil)
	writeFixtureFile(t, dir, "database-url", []byte("postgresql://lindm@db1/lindm?sslmode=verify-full&sslrootcert=root.crt"))
	database := &configv1.DatabaseConfig{UrlFile: "database-url", MaxConnections: 8}
	d := &Document{Proto: &configv1.ServerConfig{Database: database}, base: dir}
	for _, tc := range []struct {
		admin *uint32
		want  int32
	}{{nil, DefaultAdminConnections}, {proto.Uint32(2), 2}} {
		database.AdminConnections = tc.admin
		cfg, err := d.AdminDatabase()
		if err != nil {
			t.Fatal(err)
		}
		device, err := d.Database()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MaxConns != tc.want || device.MaxConns != 8 || cfg.ConnConfig.Host != device.ConnConfig.Host || cfg.ConnConfig.User != device.ConnConfig.User {
			t.Fatalf("admin pool %d (want %d), device pool %d, same host/user %t", cfg.MaxConns, tc.want, device.MaxConns, cfg.ConnConfig.Host == device.ConnConfig.Host)
		}
	}
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []uint32{0, 65} {
		if validator.Validate(&configv1.DatabaseConfig{UrlFile: "database-url", MaxConnections: 8, AdminConnections: proto.Uint32(n)}) == nil {
			t.Errorf("admin_connections %d accepted", n)
		}
	}
}
