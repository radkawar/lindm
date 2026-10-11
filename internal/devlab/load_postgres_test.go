package devlab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoadAuthorityOptions(t *testing.T) {
	for _, options := range []LoadAuthorityOptions{
		{}, {DatabaseStorage: "shared", ServerCPUs: "0-2,12-14"},
		{DatabaseStorage: "nvme", PostgresCPUs: "4-5,16-17", ServerCPUs: "6,18"},
		{DatabaseStorage: "tmpfs", PostgresCPUs: "0"}, {ListenAddress: "127.0.0.1"},
		{DatabaseStorage: "nvme", PostgresSettings: []string{"shared_buffers=8GB", "max_wal_size=16GB"}},
	} {
		if err := options.validate(); err != nil {
			t.Errorf("valid options %+v: %v", options, err)
		}
	}
	for _, options := range []LoadAuthorityOptions{
		{DatabaseStorage: "production"}, {DatabaseStorage: "postgresql://localhost/lindm"},
		{DatabaseStorage: "shared", PostgresCPUs: "0"}, {PostgresCPUs: "0"},
		{DatabaseStorage: "tmpfs", PostgresCPUs: "0;id"}, {ServerCPUs: "-1"},
		{ServerCPUs: "2-1"}, {ServerCPUs: "1-1"}, {ServerCPUs: "1,"},
		{ServerCPUs: "1,,2"}, {ServerCPUs: "1-2-3"}, {ServerCPUs: "+2"},
		{ServerCPUs: " 2"}, {ServerCPUs: "9999999999999999999999999999999999999999999999"},
		{ListenAddress: "0.0.0.0"}, {ListenAddress: "::1"}, {ListenAddress: "localhost"},
		{ListenAddress: "192.0.2.1"}, {ListenAddress: "127.000.0.1"},
		{DatabaseStorage: "shared", PostgresSettings: []string{"shared_buffers=8GB"}},
		{DatabaseStorage: "nvme", PostgresSettings: []string{"synchronous_commit=off"}},
		{DatabaseStorage: "nvme", PostgresSettings: []string{"fsync=off"}},
		{DatabaseStorage: "nvme", PostgresSettings: []string{"work_mem=1MB;drop"}},
		{DatabaseStorage: "nvme", PostgresSettings: []string{"work_mem=1MB", "work_mem=2MB"}},
	} {
		if err := options.validate(); err == nil {
			t.Errorf("accepted invalid options %+v", options)
		}
	}
}

func TestDedicatedPostgresArgumentsStayOwnedAndPinned(t *testing.T) {
	for _, storage := range []string{"tmpfs", "nvme"} {
		t.Run(storage, func(t *testing.T) {
			options := LoadAuthorityOptions{DatabaseStorage: storage, PostgresCPUs: "4-5"}
			args := loadPostgresArgs("/repo", "/shared", "/private", options, &loadPostgresStorage{mountPath: "/owned/data"})
			joined := strings.Join(args, " ")
			for _, forbidden := range []string{"--privileged", "--device", "--network", "server.json", "migration-database-url", "transport-ca.key", "--force", "postgres-data"} {
				if strings.Contains(joined, forbidden) {
					t.Errorf("unsafe PostgreSQL argument %s", forbidden)
				}
			}
			for _, expected := range []string{loadPostgresImage, "--cpuset-cpus 4-5", "--publish 127.0.0.1::5432", "--entrypoint /bin/sh", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256", "lindm.load.owned=private"} {
				if !strings.Contains(joined, expected) {
					t.Errorf("missing PostgreSQL configuration %s", expected)
				}
			}
			for index, argument := range args {
				if argument != "--mount" {
					continue
				}
				mount := args[index+1]
				if !strings.HasSuffix(mount, ",readonly") && mount != "type=bind,src=/owned/data,dst=/var/lib/postgresql" {
					t.Errorf("non-owned writable mount %s", mount)
				}
			}
			if (storage == "tmpfs") != slices.Contains(args, "--tmpfs") {
				t.Fatal("storage mode not reflected in mounts")
			}
			if storage == "tmpfs" && !strings.Contains(joined, "size=25769803776") {
				t.Fatal("tmpfs is not capped at 24 GiB")
			}
		})
	}
	compose, err := os.ReadFile(filepath.Join("..", "..", "deploy", "dev", "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), "image: "+loadPostgresImage) {
		t.Fatal("dedicated PostgreSQL must track the maintained development image and digest")
	}
}

func TestLoadNVMeBackingRejectsUnverifiedDevices(t *testing.T) {
	good := []loadBlockDevice{{Name: "/dev/mapper/lab", Type: "crypt", Children: []loadBlockDevice{{Name: "/dev/nvme0n1p2", Type: "part", Children: []loadBlockDevice{{Name: "/dev/nvme0n1", Type: "disk"}}}}}}
	devices, err := loadNVMeDevices(good)
	if err != nil || !slices.Equal(devices, []string{"/dev/nvme0n1"}) {
		t.Fatalf("verified NVMe backing: %v, %v", devices, err)
	}
	for _, bad := range [][]loadBlockDevice{
		nil,
		{{Name: "/dev/sda", Type: "disk"}},
		{{Name: "/dev/nvme0n1p2", Type: "part"}},
		{{Name: "/dev/loop0", Type: "loop"}},
		{{Name: "/dev/nvme0n1", Type: "disk"}, {Name: "/dev/sda", Type: "disk"}},
	} {
		if _, err := loadNVMeDevices(bad); err == nil {
			t.Errorf("accepted non-NVMe or unresolved backing %+v", bad)
		}
	}
}

func TestLoadEnvironmentDoesNotExposeMutableStateOrSecrets(t *testing.T) {
	fixture := &AuthorityFixture{environment: LoadExperimentEnvironment{Storage: "storage: tmpfs (no durable fsync cost)", Image: loadPostgresImage, ImageDigest: loadPostgresDigest, BackingDevices: []string{"/dev/nvme0n1"}}}
	environment := fixture.ExperimentEnvironment()
	environment.BackingDevices[0] = "changed"
	if fixture.ExperimentEnvironment().BackingDevices[0] != "/dev/nvme0n1" {
		t.Fatal("environment caller mutated fixture state")
	}
	encoded, err := json.Marshal(environment)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"password", "secret", "postgresql://", "database_url", "dsn"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("experiment environment contains %s", forbidden)
		}
	}
}

func TestLoadPostgresEffectiveCPUs(t *testing.T) {
	cpus, err := loadPostgresEffectiveCPUs("Name:\tpostgres\nCpus_allowed:\t0000f000\nCpus_allowed_list:\t4-5,16-17\nMems_allowed_list:\t0\n")
	if err != nil || cpus != "4-5,16-17" {
		t.Fatalf("effective PostgreSQL CPUs: %q, %v", cpus, err)
	}
	for _, status := range []string{"", "Cpus_allowed:\tff\n", "Cpus_allowed_list:\t\n", "Cpus_allowed_list:\t4;echo\n"} {
		if _, err := loadPostgresEffectiveCPUs(status); err == nil {
			t.Errorf("accepted missing or invalid CPU evidence %q", status)
		}
	}
}
