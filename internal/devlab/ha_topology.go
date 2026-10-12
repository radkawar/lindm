package devlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

//go:embed ha_postgres_entrypoint.sh
var haPostgresEntrypoint []byte

// haProxyImage is HAProxy 3.2.25 LTS, pinned by its multi-architecture index.
const haProxyImage = "haproxy:3.2@sha256:89c31eabc1ce443a13a42725a04df034b992c9d60580f4e6ef8b7bf5b15deddf"

// HAInstanceNames are the stable replica names used in configs and evidence.
var HAInstanceNames = [2]string{"a", "b"}

// HAEnvironment is safe to persist: it contains no URLs, passwords or keys.
type HAEnvironment struct {
	PostgresImage    string           `json:"postgres_image"`
	ProxyImage       string           `json:"proxy_image"`
	ProxyVersion     string           `json:"proxy_version"`
	ProxyContainerID string           `json:"proxy_container_id"`
	PostgresNodes    []HAPostgresNode `json:"postgres_nodes"`
	BalancerAdmin    string           `json:"balancer_admin"`
	BalancerDevice   string           `json:"balancer_device"`
	Replication      []HAReplication  `json:"replication"`
}

type HAPostgresNode struct {
	Name        string `json:"name"`
	InitialRole string `json:"initial_role"`
	Port        int    `json:"port"`
	ContainerID string `json:"container_id"`
	Volume      string `json:"volume"`
}

// HAReplication is one pg_stat_replication row observed on the primary.
type HAReplication struct {
	ApplicationName string `json:"application_name"`
	State           string `json:"state"`
	SyncState       string `json:"sync_state"`
}

// HAInstanceState identifies one lindmd replica process.
type HAInstanceState struct {
	Name          string    `json:"name"`
	PID           int       `json:"pid"`
	Binary        string    `json:"binary"`
	BinarySHA256  string    `json:"binary_sha256"`
	AdminAddress  string    `json:"admin_address"`
	DeviceAddress string    `json:"device_address"`
	StartedAt     time.Time `json:"started_at"`
	Running       bool      `json:"running"`
	// Exit is the last process exit status, including laboratory signals.
	Exit string `json:"exit,omitempty"`
}

// HAFailover records one primary loss and standby promotion.
type HAFailover struct {
	FailedNode               string          `json:"failed_node"`
	PromotedNode             string          `json:"promoted_node"`
	KilledAt                 time.Time       `json:"killed_at"`
	PromotedAt               time.Time       `json:"promoted_at"`
	WritableAt               time.Time       `json:"writable_at"`
	ReplicationBeforeFailure []HAReplication `json:"replication_before_failure"`
}

// HALockHolder is one granted advisory lock in the authority database.
type HALockHolder struct {
	Key             int64  `json:"key"`
	ApplicationName string `json:"application_name"`
}

type haPostgresNode struct {
	HAPostgresNode
	createAttempted bool
}

type haInstance struct {
	name, config       string
	admin, device      int
	binary             string
	log                *os.File
	process            *labexec.Process
	done               chan error
	state              HAInstanceState
	binaryDigestByPath map[string]string
	logPath            string
	exit               atomic.Pointer[string]
}

// haTopology owns two PostgreSQL containers with synchronous streaming
// replication, an L4 TLS-passthrough HAProxy container and two lindmd replicas.
// All containers use host networking on loopback with reserved dynamic ports.
type haTopology struct {
	directory         string
	shared            string
	label             string
	postgresPassword  string
	migratorPassword  string
	nodes             [2]*haPostgresNode
	primary           int
	proxyID           string
	proxyCreate       bool
	proxyVersion      string
	lbAdmin, lbDevice int
	statsPort         int
	reservations      map[int]net.Listener
	instances         [2]*haInstance
	proxyBackends     []haProxyBackend
	proxyBindAddress  string
	replication       []HAReplication
}

type haProxyBackend struct {
	name, admin, device string
}

func (t *haTopology) proxyAddress() string {
	if t.proxyBindAddress != "" {
		return t.proxyBindAddress
	}
	return "127.0.0.1"
}

func haSecret() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes[:]), nil
}

func (t *haTopology) reserve() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.Join(errors.New("reservation is not TCP"), listener.Close())
	}
	t.reservations[address.Port] = listener
	return address.Port, nil
}

// release frees a reserved port immediately before its owner binds it.
func (t *haTopology) release(port int) error {
	listener, ok := t.reservations[port]
	if !ok {
		return nil
	}
	delete(t.reservations, port)
	return listener.Close()
}

func openHATopology(ctx context.Context, shared string) (_ *haTopology, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	t := &haTopology{shared: shared, reservations: make(map[int]net.Listener)}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, t.close())
		}
	}()
	var err error
	t.directory, err = os.MkdirTemp("", "lindm-ha-")
	if err != nil {
		return nil, err
	}
	t.label = "lindm.ha.owned=" + filepath.Base(t.directory)
	if t.postgresPassword, err = haSecret(); err != nil {
		return nil, err
	}
	if t.migratorPassword, err = haSecret(); err != nil {
		return nil, err
	}
	runtimePassword, err := haSecret()
	if err != nil {
		return nil, err
	}
	replicatorPassword, err := haSecret()
	if err != nil {
		return nil, err
	}
	for i := range t.nodes {
		port, err := t.reserve()
		if err != nil {
			return nil, err
		}
		t.nodes[i] = &haPostgresNode{HAPostgresNode: HAPostgresNode{Name: fmt.Sprintf("pg%d", i), Port: port, Volume: filepath.Base(t.directory) + fmt.Sprintf("-pg%d", i)}}
	}
	// The fixture reserves the balancer ports with its public origins; the
	// loopback statistics socket is private to the laboratory.
	t.nodes[0].InitialRole, t.nodes[1].InitialRole = "primary", "standby"
	if t.statsPort, err = t.reserve(); err != nil {
		return nil, err
	}
	for i, name := range HAInstanceNames {
		instance := &haInstance{name: name, binaryDigestByPath: make(map[string]string)}
		if instance.admin, err = t.reserve(); err != nil {
			return nil, err
		}
		if instance.device, err = t.reserve(); err != nil {
			return nil, err
		}
		t.instances[i] = instance
	}
	initSQL := databaseRoleSQL(t.migratorPassword, runtimePassword) +
		fmt.Sprintf("CREATE ROLE lindm_replicator LOGIN REPLICATION PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;\n", replicatorPassword) +
		applicationDatabaseSQL +
		"ALTER SYSTEM SET synchronous_standby_names = 'FIRST 1 (lindm_standby)';\n"
	for name, data := range map[string][]byte{
		"postgres-password":   []byte(t.postgresPassword),
		"database-init.sql":   []byte(initSQL),
		"replication.pgpass":  fmt.Appendf(nil, "localhost:%d:*:lindm_replicator:%s\n", t.nodes[0].Port, replicatorPassword),
		"postgres-entrypoint": haPostgresEntrypoint,
	} {
		if err := os.WriteFile(filepath.Join(t.directory, name), data, 0600); err != nil {
			return nil, err
		}
	}
	for _, node := range t.nodes {
		if err := t.startPostgres(ctx, node); err != nil {
			return nil, err
		}
		if err := t.waitPostgres(ctx, node); err != nil {
			return nil, err
		}
	}
	if err := t.waitSynchronous(ctx); err != nil {
		return nil, err
	}
	migration := t.url("lindm_migrator", t.migratorPassword, "lindm")
	if err := os.WriteFile(filepath.Join(t.directory, "migration-database-url"), []byte(migration), 0600); err != nil {
		return nil, err
	}
	return t, nil
}

// url builds a libpq multi-host URL that only accepts a writable primary.
// net/url cannot represent PostgreSQL's host list, so it is assembled here.
func (t *haTopology) url(user, password, database string) string {
	query := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {filepath.Join(t.shared, "transport-ca.crt")}, "target_session_attrs": {"read-write"}}
	return fmt.Sprintf("postgresql://%s:%s@localhost:%d,localhost:%d/%s?%s", user, url.QueryEscape(password), t.nodes[0].Port, t.nodes[1].Port, database, query.Encode())
}

func (t *haTopology) databaseURL(database string) string {
	return t.url("lindm_migrator", t.migratorPassword, database)
}

func (t *haTopology) adminConfig(port int) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(t.url("postgres", t.postgresPassword, "postgres"))
	if err != nil {
		return nil, errors.New("invalid HA administration configuration")
	}
	cfg.ConnectTimeout = 3 * time.Second
	if port != 0 {
		cfg.Port = uint16(port)
		cfg.Fallbacks = nil
		cfg.ValidateConnect = nil
	}
	return cfg, nil
}

func (t *haTopology) startPostgres(ctx context.Context, node *haPostgresNode) error {
	if _, err := loadDocker(ctx, "volume", "create", "--label", t.label, node.Volume); err != nil {
		return err
	}
	args := []string{"create", "--label", t.label, "--network", "host", "--security-opt", "no-new-privileges:true",
		"--env", "PGPORT=" + strconv.Itoa(node.Port), "--env", "LINDM_HA_ROLE=" + node.InitialRole,
		"--env", "POSTGRES_DB=lindm", "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
		"--mount", "type=volume,src=" + node.Volume + ",dst=/var/lib/postgresql",
		"--mount", "type=bind,src=" + filepath.Join(t.directory, "postgres-entrypoint") + ",dst=/opt/lindm/postgres-entrypoint.sh,readonly",
	}
	if node.InitialRole == "standby" {
		args = append(args, "--env", "LINDM_HA_PRIMARY_PORT="+strconv.Itoa(t.nodes[0].Port))
	}
	for _, name := range []string{"server.crt", "server.key", "transport-ca.crt"} {
		args = append(args, "--mount", "type=bind,src="+filepath.Join(t.shared, name)+",dst=/run/lindm-ha/"+name+",readonly")
	}
	for _, name := range []string{"postgres-password", "database-init.sql", "replication.pgpass"} {
		args = append(args, "--mount", "type=bind,src="+filepath.Join(t.directory, name)+",dst=/run/lindm-ha/"+name+",readonly")
	}
	args = append(args, "--entrypoint", "/bin/sh", loadPostgresImage, "/opt/lindm/postgres-entrypoint.sh")
	node.createAttempted = true
	output, err := loadDocker(ctx, args...)
	if err != nil {
		return err
	}
	id := strings.TrimSpace(string(output))
	if !loadContainerIDPattern.MatchString(id) {
		return errors.New("docker did not return an exact owned HA PostgreSQL container ID")
	}
	node.ContainerID = id
	if err := t.release(node.Port); err != nil {
		return err
	}
	_, err = loadDocker(ctx, "start", id)
	return err
}

func (t *haTopology) waitPostgres(ctx context.Context, node *haPostgresNode) error {
	cfg, err := t.adminConfig(node.Port)
	if err != nil {
		return err
	}
	return pollUntil(ctx, 3*time.Minute, func(ctx context.Context) (bool, error) {
		conn, err := pgx.ConnectConfig(ctx, cfg.Copy())
		if err != nil {
			return false, nil
		}
		return true, conn.Close(ctx)
	})
}

// waitSynchronous requires the standby to be an attached synchronous replica
// before any authority data is written.
func (t *haTopology) waitSynchronous(ctx context.Context) error {
	return pollUntil(ctx, 2*time.Minute, func(ctx context.Context) (bool, error) {
		rows, err := t.replicationStatus(ctx)
		if err != nil {
			return false, nil
		}
		for _, row := range rows {
			if row.ApplicationName == "lindm_standby" && row.State == "streaming" && row.SyncState == "sync" {
				t.replication = rows
				return true, nil
			}
		}
		return false, nil
	})
}

func (t *haTopology) replicationStatus(ctx context.Context) (_ []HAReplication, resultErr error) {
	cfg, err := t.adminConfig(t.nodes[t.primary].Port)
	if err != nil {
		return nil, err
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, conn.Close(context.WithoutCancel(ctx))) }()
	rows, err := conn.Query(ctx, "SELECT application_name, state, sync_state FROM pg_stat_replication ORDER BY application_name")
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (HAReplication, error) {
		var r HAReplication
		return r, row.Scan(&r.ApplicationName, &r.State, &r.SyncState)
	})
}

func pollUntil(ctx context.Context, limit time.Duration, check func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		attempt, stop := context.WithTimeout(ctx, 5*time.Second)
		done, err := check(attempt)
		stop()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("HA laboratory readiness: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// writeInstanceConfigs derives each stopped replica's configuration from the
// checked base document, changing only its listener ports. The fixture calls it
// again before a full restart so base configuration changes reach every replica.
func (t *haTopology) writeInstanceConfigs(base *configv1.ServerConfig, directory string) error {
	for _, instance := range t.instances {
		if instance.process != nil {
			return fmt.Errorf("HA instance %s is running; its configuration is immutable", instance.name)
		}
		cfg := proto.CloneOf(base)
		cfg.AdminListener = &configv1.ListenerConfig{Address: "127.0.0.1", Port: uint32(instance.admin)}
		cfg.DeviceListener = &configv1.ListenerConfig{Address: "127.0.0.1", Port: uint32(instance.device)}
		encoded, err := protojson.Marshal(cfg)
		if err != nil {
			return err
		}
		instance.config = filepath.Join(directory, "instance-"+instance.name+".json")
		if err := os.WriteFile(instance.config, encoded, 0600); err != nil {
			return err
		}
		if instance.log == nil {
			instance.logPath = filepath.Join(directory, "instance-"+instance.name+".log")
			if instance.log, err = os.OpenFile(instance.logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0600); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *haTopology) haproxyConfig() string {
	var b strings.Builder
	maxConnections := 4096
	if len(t.proxyBackends) != 0 {
		// The capacity fixture must admit 20k independently authenticated
		// device connections plus admin traffic without a 4096-session cap.
		maxConnections = 65536
	}
	fmt.Fprintf(&b, `global
  log stdout format iso local0
  maxconn %d
  stats socket ipv4@127.0.0.1:%d level user
defaults
  mode tcp
  log global
  option dontlog-normal
  option log-health-checks
  timeout connect 1s
  timeout client 120s
  timeout server 120s
  timeout check 2s
  retries 3
  option redispatch 1
  default-server inter 500ms fastinter 250ms downinter 1s fall 2 rise 2 check-ssl verify required ca-file /usr/local/etc/haproxy/transport-ca.crt check-sni localhost verifyhost localhost
frontend admin
  bind %s:%d
  default_backend admin
frontend device
  bind %s:%d
  default_backend device
`, maxConnections, t.statsPort, t.proxyAddress(), t.lbAdmin, t.proxyAddress(), t.lbDevice)
	backends := t.proxyBackends
	if len(backends) == 0 {
		for _, instance := range t.instances {
			backends = append(backends, haProxyBackend{name: instance.name,
				admin:  net.JoinHostPort("127.0.0.1", strconv.Itoa(instance.admin)),
				device: net.JoinHostPort("127.0.0.1", strconv.Itoa(instance.device))})
		}
	}
	for _, backend := range []string{"admin", "device"} {
		fmt.Fprintf(&b, "backend %s\n  balance roundrobin\n  option httpchk\n  http-check send meth GET uri /readyz ver HTTP/1.1 hdr Host localhost\n  http-check expect status 204\n", backend)
		for _, instance := range backends {
			address := instance.admin
			if backend == "device" {
				address = instance.device
			}
			_, port, _ := net.SplitHostPort(instance.admin)
			fmt.Fprintf(&b, "  server %s %s check port %s\n", instance.name, address, port)
		}
	}
	return b.String()
}

func (t *haTopology) startProxy(ctx context.Context) error {
	if t.proxyID != "" {
		return nil
	}
	ca, err := os.ReadFile(filepath.Join(t.shared, "transport-ca.crt"))
	if err != nil {
		return err
	}
	// HAProxy runs unprivileged in its container; these inputs are public.
	for name, data := range map[string][]byte{"haproxy.cfg": []byte(t.haproxyConfig()), "proxy-ca.crt": ca} {
		path := filepath.Join(t.directory, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
		if err := os.Chmod(path, 0644); err != nil {
			return err
		}
	}
	t.proxyCreate = true
	output, err := loadDocker(ctx, "create", "--label", t.label, "--network", "host", "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
		"--mount", "type=bind,src="+filepath.Join(t.directory, "haproxy.cfg")+",dst=/usr/local/etc/haproxy/haproxy.cfg,readonly",
		"--mount", "type=bind,src="+filepath.Join(t.directory, "proxy-ca.crt")+",dst=/usr/local/etc/haproxy/transport-ca.crt,readonly",
		haProxyImage, "haproxy", "-W", "-db", "-f", "/usr/local/etc/haproxy/haproxy.cfg")
	if err != nil {
		return err
	}
	id := strings.TrimSpace(string(output))
	if !loadContainerIDPattern.MatchString(id) {
		return errors.New("docker did not return an exact owned HAProxy container ID")
	}
	t.proxyID = id
	if err := errors.Join(t.release(t.lbAdmin), t.release(t.lbDevice), t.release(t.statsPort)); err != nil {
		return err
	}
	if _, err := loadDocker(ctx, "start", id); err != nil {
		return err
	}
	version, err := loadDocker(ctx, "exec", id, "haproxy", "-v")
	if err != nil {
		return err
	}
	t.proxyVersion, _, _ = strings.Cut(string(version), "\n")
	return pollUntil(ctx, time.Minute, func(ctx context.Context) (bool, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(t.proxyAddress(), strconv.Itoa(t.lbAdmin)))
		if err != nil {
			return false, nil
		}
		return true, conn.Close()
	})
}

func (t *haTopology) instance(name string) (*haInstance, error) {
	for _, instance := range t.instances {
		if instance.name == name {
			return instance, nil
		}
	}
	return nil, fmt.Errorf("unknown HA instance %q", name)
}

// startInstance starts one replica and waits for its own readiness endpoint.
func (t *haTopology) startInstance(ctx context.Context, instance *haInstance, binary string, client *http.Client) error {
	if instance.process != nil {
		return fmt.Errorf("HA instance %s is already running", instance.name)
	}
	digest, ok := instance.binaryDigestByPath[binary]
	if !ok {
		data, err := os.ReadFile(binary)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		digest = hex.EncodeToString(sum[:])
		instance.binaryDigestByPath[binary] = digest
	}
	if err := errors.Join(t.release(instance.admin), t.release(instance.device)); err != nil {
		return err
	}
	command, err := newServerCommand(binary, instance.config, "")
	if err != nil {
		return err
	}
	command.Stdout, command.Stderr = instance.log, instance.log
	instance.exit.Store(nil)
	// The replica outlives this call; signalInstance owns its lifetime.
	process, err := labexec.Start(context.WithoutCancel(ctx), command)
	if err != nil {
		return fmt.Errorf("start HA instance %s failed", instance.name)
	}
	instance.process, instance.done, instance.binary = process, make(chan error, 1), binary
	instance.state = HAInstanceState{Name: instance.name, PID: process.Pid(), Binary: filepath.Base(binary), BinarySHA256: digest,
		AdminAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(instance.admin)), DeviceAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(instance.device)), StartedAt: time.Now().UTC(), Running: true}
	done := instance.done
	go func() {
		err := process.Wait()
		status := "exit status 0"
		if err != nil {
			status = err.Error()
		}
		instance.exit.Store(&status)
		done <- err
	}()
	origin := fmt.Sprintf("https://localhost:%d/readyz", instance.admin)
	return pollUntil(ctx, 45*time.Second, func(ctx context.Context) (bool, error) {
		select {
		case <-instance.done:
			instance.process, instance.done, instance.state.Running = nil, nil, false
			return false, fmt.Errorf("HA instance %s exited before readiness", instance.name)
		default:
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin, nil)
		if err != nil {
			return false, err
		}
		response, err := client.Do(request)
		if err != nil {
			return false, nil
		}
		closeErr := response.Body.Close()
		return response.StatusCode == http.StatusNoContent && closeErr == nil, nil
	})
}

// signalInstance delivers SIGTERM (graceful drain) or SIGKILL (crash) and joins.
func (t *haTopology) signalInstance(instance *haInstance, signal syscall.Signal) error {
	if instance.process == nil {
		return nil
	}
	process, done := instance.process, instance.done
	process.Signal(signal)
	timer := time.NewTimer(40 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		instance.process, instance.done, instance.state.Running = nil, nil, false
		var exit *exec.ExitError
		if signal == syscall.SIGKILL && errors.As(err, &exit) {
			return nil
		}
		return err
	case <-timer.C:
		process.Signal(syscall.SIGKILL)
		<-done
		instance.process, instance.done, instance.state.Running = nil, nil, false
		return fmt.Errorf("HA instance %s required forced shutdown", instance.name)
	}
}

// failOver crashes the current primary container and promotes the standby.
func (t *haTopology) failOver(ctx context.Context) (HAFailover, error) {
	if t.primary != 0 {
		return HAFailover{}, errors.New("HA laboratory supports one promotion per topology")
	}
	before, err := t.replicationStatus(ctx)
	if err != nil {
		return HAFailover{}, err
	}
	failed, promoted := t.nodes[0], t.nodes[1]
	result := HAFailover{FailedNode: failed.Name, PromotedNode: promoted.Name, ReplicationBeforeFailure: before}
	// Record the request time: the container may die before docker returns.
	result.KilledAt = time.Now().UTC()
	if _, err := loadDocker(ctx, "kill", "--signal", "KILL", failed.ContainerID); err != nil {
		return result, err
	}
	if _, err := loadDocker(ctx, "exec", "--user", "postgres", promoted.ContainerID, "sh", "-c", `exec pg_ctl promote -w -t 60 -D "$PGDATA"`); err != nil {
		return result, err
	}
	result.PromotedAt = time.Now().UTC()
	t.primary = 1
	cfg, err := t.adminConfig(0)
	if err != nil {
		return result, err
	}
	err = pollUntil(ctx, time.Minute, func(ctx context.Context) (bool, error) {
		conn, err := pgx.ConnectConfig(ctx, cfg.Copy())
		if err != nil {
			return false, nil
		}
		var recovering bool
		scanErr := conn.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&recovering)
		return scanErr == nil && !recovering, conn.Close(ctx)
	})
	result.WritableAt = time.Now().UTC()
	return result, err
}

// lockHolders lists granted advisory locks in the named database.
func (t *haTopology) lockHolders(ctx context.Context, database string) (_ []HALockHolder, resultErr error) {
	cfg, err := t.adminConfig(0)
	if err != nil {
		return nil, err
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, conn.Close(context.WithoutCancel(ctx))) }()
	rows, err := conn.Query(ctx, `SELECT ((l.classid::bigint << 32) | l.objid::bigint), a.application_name
FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid JOIN pg_database d ON d.oid = l.database
WHERE l.locktype = 'advisory' AND l.objsubid = 1 AND l.granted AND d.datname = $1 ORDER BY 1`, database)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (HALockHolder, error) {
		var holder HALockHolder
		return holder, row.Scan(&holder.Key, &holder.ApplicationName)
	})
}

func (t *haTopology) environment() HAEnvironment {
	environment := HAEnvironment{PostgresImage: loadPostgresImage, ProxyImage: haProxyImage, ProxyVersion: t.proxyVersion, ProxyContainerID: t.proxyID,
		BalancerAdmin: net.JoinHostPort("127.0.0.1", strconv.Itoa(t.lbAdmin)), BalancerDevice: net.JoinHostPort("127.0.0.1", strconv.Itoa(t.lbDevice)),
		Replication: append([]HAReplication(nil), t.replication...)}
	for _, node := range t.nodes {
		if node != nil {
			environment.PostgresNodes = append(environment.PostgresNodes, node.HAPostgresNode)
		}
	}
	return environment
}

const haLogLimit = 64 << 20

// instanceLog returns the replica's bounded structured server log.
func (t *haTopology) instanceLog(name string) (_ []byte, resultErr error) {
	instance, err := t.instance(name)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(instance.logPath)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	var buffer bytes.Buffer
	if _, err := io.Copy(&buffer, io.LimitReader(file, haLogLimit+1)); err != nil {
		return nil, err
	}
	if buffer.Len() > haLogLimit {
		return nil, errors.New("HA instance log exceeds its evidence bound")
	}
	return buffer.Bytes(), nil
}

func (t *haTopology) proxyLog(ctx context.Context) (string, error) {
	if t.proxyID == "" {
		return "", errors.New("HAProxy is not running")
	}
	// Diagnostics, not parsed: the most recent haLogLimit bytes are kept.
	output := nativeexec.NewTailBuffer(haLogLimit)
	if err := loadDockerInto(ctx, output, "logs", t.proxyID); err != nil {
		return "", err
	}
	return output.String(), nil
}

// serverStates reads "backend/server" health from HAProxy's loopback
// statistics socket, e.g. {"device/a": "UP"}.
func (t *haTopology) serverStates(ctx context.Context) (_ map[string]string, resultErr error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(t.statsPort)))
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, conn.Close()) }()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if _, err := io.WriteString(conn, "show stat\n"); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil {
		return nil, err
	}
	states := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ",")
		// pxname,svname,...; status is the 18th CSV column.
		if len(fields) < 18 || strings.HasPrefix(line, "#") || fields[1] == "FRONTEND" || fields[1] == "BACKEND" {
			continue
		}
		states[fields[0]+"/"+fields[1]] = fields[17]
	}
	return states, nil
}

func (t *haTopology) stopInstances() error {
	var err error
	for _, instance := range t.instances {
		if instance != nil {
			err = errors.Join(err, t.signalInstance(instance, syscall.SIGTERM))
		}
	}
	return err
}

func (t *haTopology) running() bool {
	for _, instance := range t.instances {
		if instance != nil && instance.process != nil {
			return true
		}
	}
	return false
}

// close removes only exactly identified owned containers and volumes. It never
// forces removal of a container that failed to stop.
func (t *haTopology) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	for port := range t.reservations {
		err = errors.Join(err, t.release(port))
	}
	for _, instance := range t.instances {
		if instance != nil && instance.log != nil {
			err = errors.Join(err, instance.log.Close())
			instance.log = nil
		}
	}
	if t.proxyCreate && t.proxyID == "" || anyCreateAttempted(t.nodes) {
		if recoverErr := t.recoverContainerIDs(ctx); recoverErr != nil {
			return errors.Join(err, recoverErr)
		}
	}
	if t.proxyID != "" {
		if _, stopErr := loadDocker(ctx, "stop", "--time", "10", t.proxyID); stopErr != nil {
			return errors.Join(err, fmt.Errorf("HAProxy container %s and resources %s retained: %w", t.proxyID, t.directory, stopErr))
		}
		if _, rmErr := loadDocker(ctx, "rm", t.proxyID); rmErr != nil {
			return errors.Join(err, fmt.Errorf("HAProxy container %s and resources %s retained: %w", t.proxyID, t.directory, rmErr))
		}
		t.proxyID, t.proxyCreate = "", false
	}
	for _, node := range t.nodes {
		if node == nil || !node.createAttempted {
			continue
		}
		if node.ContainerID != "" {
			if _, stopErr := loadDocker(ctx, "stop", "--time", "30", node.ContainerID); stopErr != nil {
				return errors.Join(err, fmt.Errorf("HA PostgreSQL container %s and resources %s retained: %w", node.ContainerID, t.directory, stopErr))
			}
			if _, rmErr := loadDocker(ctx, "rm", node.ContainerID); rmErr != nil {
				return errors.Join(err, fmt.Errorf("HA PostgreSQL container %s and resources %s retained: %w", node.ContainerID, t.directory, rmErr))
			}
			node.ContainerID = ""
		}
		if _, rmErr := loadDocker(ctx, "volume", "rm", node.Volume); rmErr != nil {
			return errors.Join(err, fmt.Errorf("HA PostgreSQL volume %s and resources %s retained: %w", node.Volume, t.directory, rmErr))
		}
		node.createAttempted = false
	}
	if t.directory != "" {
		err = errors.Join(err, os.RemoveAll(t.directory))
		t.directory = ""
	}
	return err
}

func anyCreateAttempted(nodes [2]*haPostgresNode) bool {
	for _, node := range nodes {
		if node != nil && node.createAttempted && node.ContainerID == "" {
			return true
		}
	}
	return false
}

// recoverContainerIDs maps a cancelled create to its exact owned container by
// the unique label and image, never by name or a broad filter.
func (t *haTopology) recoverContainerIDs(ctx context.Context) error {
	output, err := loadDocker(ctx, "ps", "--all", "--no-trunc", "--filter", "label="+t.label, "--format", "{{.ID}} {{.Image}} {{.Command}}")
	if err != nil {
		return fmt.Errorf("HA laboratory resources retained at %s: %w", t.directory, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !loadContainerIDPattern.MatchString(fields[0]) {
			continue
		}
		switch {
		case fields[1] == haProxyImage && t.proxyCreate && t.proxyID == "":
			t.proxyID = fields[0]
		case fields[1] == loadPostgresImage:
			for _, node := range t.nodes {
				if node != nil && node.createAttempted && node.ContainerID == "" {
					inspect, err := loadDocker(ctx, "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", fields[0])
					if err == nil && strings.Contains(string(inspect), "PGPORT="+strconv.Itoa(node.Port)+"\n") {
						node.ContainerID = fields[0]
					}
				}
			}
		}
	}
	return nil
}
