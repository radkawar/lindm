package devlab

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const loadPostgresImage = "postgres:18.6@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336"
const loadPostgresDigest = "sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336"
const loadPostgresTmpfsBytes int64 = 24 << 30

var loadContainerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// LoadAuthorityOptions selects only maintained, local lab database resources.
// No connection URL, Docker endpoint, image override or host device is accepted.
type LoadAuthorityOptions struct {
	DatabaseStorage string
	PostgresCPUs    string
	ServerCPUs      string
}

// LoadExperimentEnvironment is safe to persist: it contains no URLs or secrets.
// NVMe means an owned sparse loop/XFS file, not an exclusive physical device.
type LoadExperimentEnvironment struct {
	Storage               string   `json:"storage"`
	Image                 string   `json:"image,omitempty"`
	ImageDigest           string   `json:"image_digest,omitempty"`
	ContainerID           string   `json:"container_id,omitempty"`
	PostgresCPUs          string   `json:"postgres_cpus,omitempty"`
	PostgresEffectiveCPUs string   `json:"postgres_effective_cpus,omitempty"`
	ServerCPUs            string   `json:"server_cpus,omitempty"`
	MountPath             string   `json:"mount_path,omitempty"`
	Filesystem            string   `json:"filesystem,omitempty"`
	BackingFile           string   `json:"backing_file,omitempty"`
	BackingMount          string   `json:"backing_mount,omitempty"`
	BackingFilesystem     string   `json:"backing_filesystem,omitempty"`
	BackingSource         string   `json:"backing_source,omitempty"`
	BackingDevices        []string `json:"backing_devices,omitempty"`
	LoopDevice            string   `json:"loop_device,omitempty"`
	StorageLimitBytes     int64    `json:"storage_limit_bytes,omitempty"`
}

func (f *AuthorityFixture) ExperimentEnvironment() LoadExperimentEnvironment {
	environment := f.environment
	environment.BackingDevices = append([]string(nil), environment.BackingDevices...)
	return environment
}

func validateLoadCPUList(value string) error {
	if value == "" {
		return nil
	}
	for _, part := range strings.Split(value, ",") {
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return errors.New("CPU set must contain comma-separated numbers or ascending ranges")
		}
		previous := -1
		for _, bound := range bounds {
			if bound == "" || strings.Trim(bound, "0123456789") != "" {
				return errors.New("CPU set must contain comma-separated numbers or ascending ranges")
			}
			number, err := strconv.Atoi(bound)
			if err != nil || number < 0 || number <= previous {
				return errors.New("CPU set contains an invalid or non-ascending range")
			}
			previous = number
		}
	}
	return nil
}

func (o LoadAuthorityOptions) validate() error {
	switch o.DatabaseStorage {
	case "", "shared":
		if o.PostgresCPUs != "" {
			return errors.New("postgres CPU isolation requires dedicated nvme or tmpfs storage; shared PostgreSQL is never changed")
		}
	case "nvme", "tmpfs":
	default:
		return errors.New("database storage must be shared, nvme or tmpfs")
	}
	return errors.Join(validateLoadCPUList(o.PostgresCPUs), validateLoadCPUList(o.ServerCPUs))
}

// OpenLoadAuthorityFixture preserves the ordinary fixture while opting into an
// exact-owned dedicated cluster. It still requires verified development trust.
func OpenLoadAuthorityFixture(ctx context.Context, repository, binary string, options LoadAuthorityOptions) (*AuthorityFixture, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	return openAuthorityFixtureWithOptions(ctx, repository, binary, authorityKeycloak, options)
}

type loadPostgres struct {
	directory       string
	containerID     string
	storage         *loadPostgresStorage
	environment     LoadExperimentEnvironment
	createAttempted bool
}

// Never inherit a Docker context/DOCKER_HOST that could address a remote daemon.
func loadDocker(ctx context.Context, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
	command.WaitDelay = 5 * time.Second
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("local dedicated PostgreSQL Docker %s failed", args[0])
	}
	return output, nil
}

func loadPostgresArgs(repository, shared, directory string, options LoadAuthorityOptions, storage *loadPostgresStorage) []string {
	args := []string{"create", "--cidfile", filepath.Join(directory, "container-id"), "--label", "lindm.load.owned=" + filepath.Base(directory), "--publish", "127.0.0.1::5432", "--env", "POSTGRES_DB=lindm", "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256", "--security-opt", "no-new-privileges:true"}
	if options.PostgresCPUs != "" {
		args = append(args, "--cpuset-cpus", options.PostgresCPUs)
	}
	if options.DatabaseStorage == "tmpfs" {
		args = append(args, "--tmpfs", "/var/lib/postgresql:rw,nosuid,nodev,size=25769803776")
	} else {
		args = append(args, "--mount", "type=bind,src="+storage.mountPath+",dst=/var/lib/postgresql")
	}
	for _, name := range []string{"server.crt", "server.key"} {
		args = append(args, "--mount", "type=bind,src="+filepath.Join(shared, name)+",dst=/run/lindm-dev/"+name+",readonly")
	}
	for _, name := range []string{"postgres-password", "database-init.sql"} {
		args = append(args, "--mount", "type=bind,src="+filepath.Join(directory, name)+",dst=/run/lindm-dev/"+name+",readonly")
	}
	return append(args, "--mount", "type=bind,src="+filepath.Join(repository, "deploy/dev/postgres-entrypoint.sh")+",dst=/opt/lindm/postgres-entrypoint.sh,readonly", "--entrypoint", "/bin/sh", loadPostgresImage, "/opt/lindm/postgres-entrypoint.sh")
}

func openLoadPostgres(ctx context.Context, repository, shared string, options LoadAuthorityOptions) (_ *loadPostgres, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cluster := &loadPostgres{environment: LoadExperimentEnvironment{Image: loadPostgresImage, ImageDigest: loadPostgresDigest, PostgresCPUs: options.PostgresCPUs, ServerCPUs: options.ServerCPUs}}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, cluster.Close())
		}
	}()
	var err error
	cluster.directory, err = os.MkdirTemp("", "lindm-load-postgres-")
	if err != nil {
		return nil, err
	}
	secrets := make(map[string]string, 3)
	for _, name := range []string{"postgres-password", "migrator-password", "runtime-password"} {
		var bytes [32]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			return nil, err
		}
		secrets[name] = base64.RawURLEncoding.EncodeToString(bytes[:])
	}
	for name, data := range map[string]string{"postgres-password": secrets["postgres-password"], "database-init.sql": databaseRoleSQL(secrets["migrator-password"], secrets["runtime-password"]) + applicationDatabaseSQL} {
		if err := os.WriteFile(filepath.Join(cluster.directory, name), []byte(data), 0600); err != nil {
			return nil, err
		}
	}
	if options.DatabaseStorage == "nvme" {
		cluster.storage, err = openLoadPostgresStorage(ctx, repository)
		if err != nil {
			return nil, err
		}
		cluster.storage.describe(&cluster.environment)
	} else {
		cluster.environment.Storage = "storage: tmpfs (no durable fsync cost)"
		cluster.environment.Filesystem = "tmpfs"
		cluster.environment.MountPath = "/var/lib/postgresql"
		cluster.environment.StorageLimitBytes = loadPostgresTmpfsBytes
	}
	cluster.createAttempted = true
	output, err := loadDocker(ctx, loadPostgresArgs(repository, shared, cluster.directory, options, cluster.storage)...)
	if err != nil {
		return nil, err
	}
	cluster.containerID = strings.TrimSpace(string(output))
	if !loadContainerIDPattern.MatchString(cluster.containerID) {
		cluster.containerID = ""
		return nil, errors.New("docker did not return an exact owned container ID")
	}
	cluster.environment.ContainerID = cluster.containerID
	if _, err := loadDocker(ctx, "start", cluster.containerID); err != nil {
		return nil, err
	}
	output, err = loadDocker(ctx, "inspect", "--format", "{{json .NetworkSettings.Ports}}", cluster.containerID)
	if err != nil {
		return nil, err
	}
	var ports map[string][]struct {
		HostIP   string
		HostPort string
	}
	if err := json.Unmarshal(output, &ports); err != nil {
		return nil, errors.New("invalid dedicated PostgreSQL port mapping")
	}
	bindings := ports["5432/tcp"]
	if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" {
		return nil, errors.New("dedicated PostgreSQL requires exactly one loopback port")
	}
	port, err := strconv.Atoi(bindings[0].HostPort)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid dedicated PostgreSQL loopback port")
	}
	migrationURL := url.URL{Scheme: "postgresql", User: url.UserPassword("lindm_migrator", secrets["migrator-password"]), Host: net.JoinHostPort("localhost", strconv.Itoa(port)), Path: "/lindm"}
	migrationURL.RawQuery = url.Values{"sslmode": {"verify-full"}, "sslrootcert": {filepath.Join(shared, "transport-ca.crt")}}.Encode()
	if err := os.WriteFile(filepath.Join(cluster.directory, "migration-database-url"), []byte(migrationURL.String()), 0600); err != nil {
		return nil, err
	}
	configuration, err := pgx.ParseConfig(migrationURL.String())
	if err != nil {
		return nil, errors.New("invalid dedicated PostgreSQL TLS configuration")
	}
	configuration.ConnectTimeout = 2 * time.Second
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := pgx.ConnectConfig(ctx, configuration.Copy())
		if err == nil {
			closeContext, stop := context.WithTimeout(context.Background(), 5*time.Second)
			err = connection.Close(closeContext)
			stop()
			if err != nil {
				return nil, errors.New("close dedicated PostgreSQL readiness connection failed")
			}
			containerCPUs, err := loadDocker(ctx, "inspect", "--format", "{{.HostConfig.CpusetCpus}}", cluster.containerID)
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(string(containerCPUs)) != options.PostgresCPUs {
				return nil, errors.New("dedicated PostgreSQL container CPU configuration differs from requested isolation")
			}
			status, err := loadDocker(ctx, "exec", cluster.containerID, "cat", "/proc/1/status")
			if err != nil {
				return nil, err
			}
			cluster.environment.PostgresEffectiveCPUs, err = loadPostgresEffectiveCPUs(string(status))
			if err != nil {
				return nil, err
			}
			return cluster, nil
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("dedicated PostgreSQL TLS readiness exceeded two-minute startup deadline")
		case <-ticker.C:
		}
	}
}

func loadPostgresEffectiveCPUs(status string) (string, error) {
	for _, line := range strings.Split(status, "\n") {
		if value, ok := strings.CutPrefix(line, "Cpus_allowed_list:"); ok {
			value = strings.TrimSpace(value)
			if value == "" || validateLoadCPUList(value) != nil {
				return "", errors.New("dedicated PostgreSQL reported an invalid effective CPU mask")
			}
			return value, nil
		}
	}
	return "", errors.New("dedicated PostgreSQL did not report its effective CPU mask")
}

func (p *loadPostgres) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if p.createAttempted && p.containerID == "" {
		// A cancelled create can have reached Docker before its reply arrived.
		// Discover only our unique label, then operate solely on its exact ID.
		output, err := loadDocker(ctx, "ps", "--all", "--no-trunc", "--quiet", "--filter", "label=lindm.load.owned="+filepath.Base(p.directory))
		if err != nil {
			return fmt.Errorf("dedicated PostgreSQL resources retained at %s: %w", p.directory, err)
		}
		id := strings.TrimSpace(string(output))
		if id != "" && !loadContainerIDPattern.MatchString(id) {
			return errors.New("cannot recover a single exact owned PostgreSQL container ID")
		}
		p.containerID = id
	}
	if p.containerID != "" {
		if _, err := loadDocker(ctx, "stop", "--time", "30", p.containerID); err != nil {
			return fmt.Errorf("dedicated PostgreSQL container %s and resources %s retained: %w", p.containerID, p.directory, err)
		}
		// No force: failure retains the backing mount rather than risking live data.
		if _, err := loadDocker(ctx, "rm", p.containerID); err != nil {
			return fmt.Errorf("dedicated PostgreSQL container %s and resources %s retained: %w", p.containerID, p.directory, err)
		}
		p.containerID = ""
	}
	p.createAttempted = false
	if p.storage != nil {
		if err := p.storage.close(ctx); err != nil {
			return err
		}
	}
	if p.directory != "" {
		if err := os.RemoveAll(p.directory); err != nil {
			return err
		}
		p.directory = ""
	}
	return nil
}
