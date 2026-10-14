// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

const loadPostgresImage = "postgres:18.6@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336"
const loadPostgresDigest = "sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336"
const loadPostgresTmpfsBytes int64 = 24 << 30

var loadContainerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// LoadAuthorityOptions selects only maintained, local lab database resources.
// No connection URL, Docker endpoint, image override or host device is accepted.
type LoadAuthorityOptions struct {
	DatabaseStorage       string
	PostgresCPUs          string
	ServerCPUs            string
	nativeReleasePackages *NativeReleasePackages
	// setupCodeOut leaves the fresh owner ceremony for the real browser reviewer.
	// Only the dedicated disposable setup fixture sets this private option.
	setupCodeOut *string
	// networkContainer joins dedicated PostgreSQL to that exact container's
	// network namespace (shared by the caller) instead of publishing a port.
	networkContainer    string
	airgap              *AirgapAuthorityOptions
	splitDevice         netip.Addr
	persistentDirectory string
	// publicHost names the console and device origins instead of localhost so
	// installers can reach them through a lab-owned hosts entry.
	publicHost string
	// stockEnrollment suppresses the separate mutable TUF fixture; native
	// repositories come exclusively from the authenticated server artifact.
	stockEnrollment bool
	// missingEnrollmentArtifact isolates the executable without its adjacent
	// bundle for the real console's missing-artifact review.
	missingEnrollmentArtifact bool
	// ListenAddress binds admin/device listeners to one local IPv4 address
	// (default loopback) so a generator on another host can reach them. TLS
	// names and signed origins are unchanged; clients dial this address.
	ListenAddress string
	// PostgresListenAddress exposes only the owned durable cluster on this
	// specific local IPv4 address, with a matching verified TLS certificate.
	PostgresListenAddress string
	// Advisories enables real feed refresh/evaluation in the server under test.
	Advisories *configv1.AdvisoryConfig
	// PostgresSettings are allowlisted durable-safe server parameters for the
	// dedicated cluster (name=value), recorded with the experiment.
	PostgresSettings []string
	// NativeEnrollmentArchitectures requires these architectures in the signed
	// stock agent artifact before this connected fixture starts; never airgap.
	NativeEnrollmentArchitectures    []string
	NativeEnrollmentSourceRepository string
}

// loadPostgresSettingNames admits capacity tuning only; durability-reducing
// parameters (fsync, synchronous_commit, full_page_writes) are never accepted.
var loadPostgresSettingNames = map[string]bool{
	"shared_buffers": true, "effective_cache_size": true, "wal_buffers": true, "max_wal_size": true,
	"min_wal_size": true, "checkpoint_timeout": true, "checkpoint_completion_target": true,
	"wal_compression": true, "work_mem": true, "maintenance_work_mem": true,
	"autovacuum_vacuum_cost_limit": true, "autovacuum_naptime": true, "autovacuum_max_workers": true,
	"effective_io_concurrency": true, "random_page_cost": true, "max_parallel_workers_per_gather": true,
}

var loadPostgresSettingValue = regexp.MustCompile(`^[A-Za-z0-9._]{1,32}$`)

func validateLoadPostgresSettings(settings []string) error {
	seen := map[string]bool{}
	for _, setting := range settings {
		name, value, ok := strings.Cut(setting, "=")
		if !ok || !loadPostgresSettingNames[name] || seen[name] || !loadPostgresSettingValue.MatchString(value) {
			return fmt.Errorf("postgres setting %q is not an allowlisted capacity parameter name=value", setting)
		}
		seen[name] = true
	}
	return nil
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
	PostgresSettings      []string `json:"postgres_settings,omitempty"`
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
	environment.PostgresSettings = append([]string(nil), environment.PostgresSettings...)
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
	if o.networkContainer != "" && (o.DatabaseStorage != "tmpfs" || !loadContainerIDPattern.MatchString(o.networkContainer)) {
		return errors.New("shared network namespace requires dedicated tmpfs PostgreSQL and an exact container ID")
	}
	if len(o.PostgresSettings) != 0 && o.DatabaseStorage != "nvme" && o.DatabaseStorage != "tmpfs" {
		return errors.New("postgres settings require a dedicated nvme or tmpfs cluster; shared PostgreSQL is never changed")
	}
	if err := validateLoadPostgresSettings(o.PostgresSettings); err != nil {
		return err
	}
	if o.PostgresListenAddress != "" {
		if o.DatabaseStorage != "nvme" || o.networkContainer != "" {
			return errors.New("direct PostgreSQL requires an owned durable nvme cluster")
		}
		if err := validateLoadListenAddress(o.PostgresListenAddress); err != nil {
			return err
		}
	}
	if o.ListenAddress != "" {
		if err := validateLoadListenAddress(o.ListenAddress); err != nil {
			return err
		}
	}
	return errors.Join(validateLoadCPUList(o.PostgresCPUs), validateLoadCPUList(o.ServerCPUs))
}

// validateLoadListenAddress admits only a literal IPv4 address assigned to a
// local interface; it never binds a wildcard.
func validateLoadListenAddress(value string) error {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.String() != value {
		return errors.New("load listen address must be a literal local IPv4 address")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok && network.IP.Equal(ip) {
			return nil
		}
	}
	return errors.New("load listen address is not assigned to a local interface")
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
	listenAddress   string
	createAttempted bool
}

// loadDocker returns the bounded stdout that callers parse; truncation fails.
func loadDocker(ctx context.Context, args ...string) ([]byte, error) {
	output := nativeexec.NewBuffer(1 << 20)
	if err := loadDockerInto(ctx, output, args...); err != nil {
		return nil, err
	}
	if output.Truncated() {
		return nil, fmt.Errorf("local dedicated PostgreSQL Docker %s output exceeds 1 MiB", args[0])
	}
	return output.Bytes(), nil
}

// loadDockerInto captures stdout into output, e.g. a log tail. It never
// inherits a Docker context/DOCKER_HOST that could address a remote daemon.
func loadDockerInto(ctx context.Context, output *nativeexec.Buffer, args ...string) error {
	if err := labexec.Run(ctx, labexec.Command{Path: "docker", Args: append([]string{"--host", "unix:///var/run/docker.sock"}, args...), Stdout: output}); err != nil {
		return fmt.Errorf("local dedicated PostgreSQL Docker %s failed", args[0])
	}
	return nil
}

func loadPostgresArgs(repository, shared, directory string, options LoadAuthorityOptions, storage *loadPostgresStorage) []string {
	network := []string{"--publish", "127.0.0.1::5432"}
	if options.PostgresListenAddress != "" {
		network = []string{"--publish", options.PostgresListenAddress + "::5432"}
	}
	if options.networkContainer != "" {
		network = []string{"--network", "container:" + options.networkContainer}
	}
	args := append([]string{"create", "--cidfile", filepath.Join(directory, "container-id"), "--label", "lindm.load.owned=" + filepath.Base(directory)}, network...)
	args = append(args, "--env", "POSTGRES_DB=lindm", "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256", "--security-opt", "no-new-privileges:true")
	if options.PostgresCPUs != "" {
		args = append(args, "--cpuset-cpus", options.PostgresCPUs)
	}
	if options.DatabaseStorage == "tmpfs" {
		args = append(args, "--tmpfs", "/var/lib/postgresql:rw,nosuid,nodev,size=25769803776")
	} else {
		args = append(args, "--mount", "type=bind,src="+storage.mountPath+",dst=/var/lib/postgresql")
	}
	for _, name := range []string{"server.crt", "server.key"} {
		source := filepath.Join(shared, name)
		if options.PostgresListenAddress != "" {
			source = filepath.Join(directory, "split-"+name)
		}
		args = append(args, "--mount", "type=bind,src="+source+",dst=/run/lindm-dev/"+name+",readonly")
	}
	for _, name := range []string{"postgres-password", "database-init.sql"} {
		args = append(args, "--mount", "type=bind,src="+filepath.Join(directory, name)+",dst=/run/lindm-dev/"+name+",readonly")
	}
	args = append(args, "--mount", "type=bind,src="+filepath.Join(repository, "deploy/dev/postgres-entrypoint.sh")+",dst=/opt/lindm/postgres-entrypoint.sh,readonly", "--entrypoint", "/bin/sh", loadPostgresImage, "/opt/lindm/postgres-entrypoint.sh")
	for _, setting := range options.PostgresSettings {
		args = append(args, "-c", setting)
	}
	return args
}

func openLoadPostgres(ctx context.Context, repository, shared string, options LoadAuthorityOptions) (_ *loadPostgres, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cluster := &loadPostgres{environment: LoadExperimentEnvironment{Image: loadPostgresImage, ImageDigest: loadPostgresDigest, PostgresCPUs: options.PostgresCPUs, ServerCPUs: options.ServerCPUs, PostgresSettings: append([]string(nil), options.PostgresSettings...)}}
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
	cluster.listenAddress = options.PostgresListenAddress
	if cluster.listenAddress != "" {
		if err := writeFixtureCertificate(shared, cluster.directory, netip.MustParseAddr(cluster.listenAddress), 24*time.Hour); err != nil {
			return nil, err
		}
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
	port := 5432
	if options.networkContainer == "" {
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
		expectedAddress := "127.0.0.1"
		if cluster.listenAddress != "" {
			expectedAddress = cluster.listenAddress
		}
		if len(bindings) != 1 || bindings[0].HostIP != expectedAddress {
			return nil, errors.New("dedicated PostgreSQL requires exactly one owned address binding")
		}
		port, err = strconv.Atoi(bindings[0].HostPort)
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid dedicated PostgreSQL loopback port")
		}
	}
	host := "localhost"
	if cluster.listenAddress != "" {
		host = cluster.listenAddress
	}
	migrationURL := url.URL{Scheme: "postgresql", User: url.UserPassword("lindm_migrator", secrets["migrator-password"]), Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: "/lindm"}
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
