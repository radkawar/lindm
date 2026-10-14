// SPDX-License-Identifier: Apache-2.0

//go:build linux && integration

package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/custody"
	"lindm/internal/labexec"
)

// TestInstallerPostgresSCRAMPlus uses the integration driver's already verified,
// cached PostgreSQL image, never its cluster, TLS material or roles. Root and the
// installer's memory-custody prerequisites are required for an exercised pass.
// The re-executed test keeps whole-process memory locking out of other tests.
// No child output is forwarded: even an unexpected driver/runtime failure must
// not publish fixture credentials. Failures expose only fixed categories.
func TestInstallerPostgresSCRAMPlus(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installation ownership policy requires root")
	}
	if os.Getenv("LINDM_INSTALL_PLUS_REEXEC") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal("postgres_plus_reexec_binary")
		}
		t.Setenv("LINDM_INSTALL_PLUS_REEXEC", "1")
		output := nativeexec.NewBuffer(64 << 10)
		defer func() { clear(output.Bytes()) }()
		if err := labexec.Run(t.Context(), labexec.Command{
			Path: binary, Args: []string{"-test.run=^TestInstallerPostgresSCRAMPlus$", "-test.timeout=5m"},
			Env: os.Environ(), Stdout: output, Stderr: io.Discard, Timeout: 5 * time.Minute,
		}); err != nil {
			// Relay only fixed fixture categories, never child or driver text.
			for _, category := range []string{
				"postgres_plus_positive_handshake", "postgres_plus_positive_query_result", "postgres_plus_positive_query",
				"postgres_plus_negative_not_certificate_binding", "postgres_plus_protocol_negative_not_binding",
				"postgres_plus_cluster_readiness", "postgres_plus_role_initialization",
				"postgres_plus_connection_configuration", "postgres_plus_connection_policy",
				"postgres_plus_protocol_client_auth_not_refused",
			} {
				if bytes.Contains(output.Bytes(), []byte(category)) {
					t.Fatal(category)
				}
			}
			t.Fatal("postgres_plus_regression_failed")
		}
		return
	}
	if err := custody.LockSecretMemory(); err != nil {
		t.Fatal("postgres_plus_memory_custody")
	}
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "PG") && value != "" {
			t.Fatal("postgres_plus_environment")
		}
	}
	driver := os.Getenv("LINDM_TEST_DATABASE_TEMPLATE_CONTAINER")
	if driver == "" {
		t.Fatal("postgres_plus_requires_integration_driver")
	}
	image := strings.TrimSpace(plusDockerOutput(t, "postgres_plus_image_inspect", "inspect", "--type=container", "--format={{.Image}}", driver))
	if !strings.HasPrefix(image, "sha256:") || !plusExactID(strings.TrimPrefix(image, "sha256:")) {
		t.Fatal("postgres_plus_image_identity")
	}
	for _, tc := range []struct {
		name      string
		database  bool
		signature x509.SignatureAlgorithm
	}{
		{name: "p256", database: true, signature: x509.ECDSAWithSHA256},
		{name: "ed25519_negative", signature: x509.PureEd25519},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := plusPrivateDirectory(t)
			plusCertificates(t, root, tc.database, tc.signature)
			container, port := plusPostgresFixture(t, root, image)
			password := make([]byte, 32)
			if _, err := rand.Read(password); err != nil {
				t.Fatal("postgres_plus_password_entropy")
			}
			defer clear(password)
			encoded := make([]byte, hex.EncodedLen(len(password)))
			hex.Encode(encoded, password)
			defer clear(encoded)
			plusInitializeRole(t, container, encoded)
			cfg := plusConnectionConfig(t, root, port, encoded)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			conn, err := pgx.ConnectConfig(ctx, cfg)
			if conn != nil {
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := conn.Close(cleanup); err != nil {
						t.Error("postgres_plus_connection_cleanup")
					}
				})
			}
			if !tc.database {
				// This fixed driver diagnostic occurs only after verified TLS and
				// advertised SCRAM-PLUS, at certificate-hash extraction. Neither
				// a TLS failure nor a bad password is an acceptable negative.
				if err == nil || !strings.Contains(err.Error(), "channel binding required but failed to get server certificate hash") ||
					!strings.Contains(err.Error(), "tls-server-end-point channel binding is undefined for certificate signature algorithm Ed25519") {
					t.Fatal("postgres_plus_negative_not_certificate_binding")
				}
				return
			}
			if err != nil {
				t.Fatal("postgres_plus_positive_handshake")
			}
			var answer int
			var runtimeRole, tls13, restricted bool
			if err := conn.QueryRow(ctx, `SELECT 42, current_user = 'plus_runtime',
    (SELECT ssl AND version = 'TLSv1.3' FROM pg_stat_ssl WHERE pid = pg_backend_pid()),
    NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls
FROM pg_roles WHERE rolname = current_user`).Scan(&answer, &runtimeRole, &tls13, &restricted); err != nil {
				t.Fatal("postgres_plus_positive_query")
			}
			if answer != 42 || !runtimeRole || !tls13 || !restricted {
				t.Fatal("postgres_plus_positive_query_result")
			}
		})
	}
	t.Run("non_plus_protocol_negative", plusRejectPlainSCRAM)
}

// This is a negative-only wire fixture, not the real PostgreSQL positive proof.
// PostgreSQL advertises PLUS whenever TLS supports it, so this fixture offers
// only plain SCRAM over verified TLS and observes that pgx closes before sending
// any SASL response. The same parsed strict policy is used by the real query.
func plusRejectPlainSCRAM(t *testing.T) {
	root := plusPrivateDirectory(t)
	plusCertificates(t, root, true, x509.ECDSAWithSHA256)
	pair, err := tls.LoadX509KeyPair(filepath.Join(root, "server.crt"), filepath.Join(root, "server.key"))
	if err != nil {
		t.Fatal("postgres_plus_protocol_certificate")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("postgres_plus_protocol_listener")
	}
	done := make(chan string, 1)
	go func() {
		defer close(done)
		done <- plusSCRAMOnlyServer(listener, pair)
	}()
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error("postgres_plus_protocol_listener_cleanup")
		}
		// Closing the listener releases Accept; accepted connections have an
		// independent ten-second deadline. Always join, including Fatal paths.
		if category := <-done; category != "" {
			t.Error(category)
		}
	})
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal("postgres_plus_protocol_port")
	}
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		t.Fatal("postgres_plus_password_entropy")
	}
	defer clear(entropy)
	password := make([]byte, hex.EncodedLen(len(entropy)))
	hex.Encode(password, entropy)
	defer clear(password)
	cfg := plusConnectionConfig(t, root, port, password)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if conn != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := conn.Close(cleanup); err != nil {
			t.Error("postgres_plus_connection_cleanup")
		}
	}
	if err == nil || !strings.Contains(err.Error(), "channel binding required but server does not support SCRAM-SHA-256-PLUS") {
		t.Fatal("postgres_plus_protocol_negative_not_binding")
	}
	select {
	case category := <-done:
		if category != "" {
			t.Fatal(category)
		}
	case <-ctx.Done():
		t.Fatal("postgres_plus_protocol_deadline")
	}
}

func plusSCRAMOnlyServer(listener net.Listener, pair tls.Certificate) (category string) {
	socket, err := listener.Accept()
	if err != nil {
		return "postgres_plus_protocol_accept"
	}
	defer func() {
		if err := socket.Close(); err != nil && category == "" {
			category = "postgres_plus_protocol_socket_cleanup"
		}
	}()
	if err := socket.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "postgres_plus_protocol_socket_deadline"
	}
	backend := pgproto3.NewBackend(socket, socket)
	message, err := backend.ReceiveStartupMessage()
	if err != nil {
		return "postgres_plus_protocol_ssl_request"
	}
	if _, ok := message.(*pgproto3.SSLRequest); !ok {
		return "postgres_plus_protocol_ssl_request"
	}
	if _, err := socket.Write([]byte{'S'}); err != nil {
		return "postgres_plus_protocol_ssl_response"
	}
	secure := tls.Server(socket, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := secure.HandshakeContext(ctx); err != nil {
		return "postgres_plus_protocol_tls"
	}
	backend = pgproto3.NewBackend(secure, secure)
	message, err = backend.ReceiveStartupMessage()
	if err != nil {
		return "postgres_plus_protocol_startup"
	}
	if _, ok := message.(*pgproto3.StartupMessage); !ok {
		return "postgres_plus_protocol_startup"
	}
	backend.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
	if err := backend.Flush(); err != nil {
		return "postgres_plus_protocol_auth_offer"
	}
	message, err = backend.Receive()
	if err == nil {
		// pgx may send Terminate when closing a rejected startup exchange.
		// It must never send a SASL/password response to the plain-only offer.
		if _, terminated := message.(*pgproto3.Terminate); !terminated {
			return "postgres_plus_protocol_client_auth_not_refused"
		}
	} else if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "postgres_plus_protocol_client_auth_not_refused"
	}
	return ""
}

func plusPrivateDirectory(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/run", "lindm-postgres-plus-test-")
	if err != nil {
		t.Fatal("postgres_plus_private_directory")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error("postgres_plus_directory_cleanup")
		}
	})
	return root
}

func plusCertificates(t *testing.T, root string, database bool, signature x509.SignatureAlgorithm) {
	t.Helper()
	// Only the public CA and online server certificate/key leave memory. Use
	// the actual installer helpers for both issuers, without a CA-key file.
	var ca *x509.Certificate
	if database {
		certificate, key, err := newDatabaseCertificateAuthority("PLUS regression database CA")
		if err != nil {
			t.Fatal("postgres_plus_database_authority")
		}
		ca = certificate
		if err := issueServerCertificate(filepath.Join(root, "server"), "PLUS regression PostgreSQL", []string{"localhost", "127.0.0.1"}, ca, key, 0, 0); err != nil {
			t.Fatal("postgres_plus_database_leaf")
		}
	} else {
		certificate, key, err := newCertificateAuthority("PLUS regression Ed25519 CA")
		if err != nil {
			t.Fatal("postgres_plus_negative_authority")
		}
		defer clear(key)
		ca = certificate
		if err := issueServerCertificate(filepath.Join(root, "server"), "PLUS regression PostgreSQL", []string{"localhost", "127.0.0.1"}, ca, key, 0, 0); err != nil {
			t.Fatal("postgres_plus_negative_leaf")
		}
	}
	if err := writeCertificate(filepath.Join(root, "ca.crt"), ca, 0, 0); err != nil {
		t.Fatal("postgres_plus_public_authority")
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(root, "server.crt"), filepath.Join(root, "server.key"))
	if err != nil {
		t.Fatal("postgres_plus_leaf_pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.SignatureAlgorithm != signature || leaf.PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatal("postgres_plus_leaf_algorithm")
	}
}

// The owned cluster has no persistent volume. The root-only source directory is
// mounted read-only, and only the runtime leaf/key are copied to postgres-owned
// tmpfs. initdb, readiness and administrative SQL all target this exact fixture.
const plusPostgresEntrypoint = `umask 077
mkdir -p /run/lindm-plus/tls /run/lindm-plus/socket
cp /run/lindm-plus-source/server.crt /run/lindm-plus/tls/server.crt
cp /run/lindm-plus-source/server.key /run/lindm-plus/tls/server.key
chown -R postgres:postgres /run/lindm-plus
export PGDATA=/var/lib/postgresql/plus
chown postgres:postgres /var/lib/postgresql
install -d -o postgres -g postgres -m 0700 "$PGDATA"
gosu postgres initdb -D "$PGDATA" --auth-local=peer --auth-host=scram-sha-256 --encoding=UTF8 --locale=C
cp /run/lindm-plus-source/pg_hba.conf "$PGDATA/pg_hba.conf"
cp /run/lindm-plus-source/postgresql.conf "$PGDATA/postgresql.conf"
chown postgres:postgres "$PGDATA/pg_hba.conf" "$PGDATA/postgresql.conf"
exec gosu postgres postgres -D "$PGDATA"
`

func plusPostgresFixture(t *testing.T, root, image string) (string, string) {
	t.Helper()
	hba := "local all postgres peer\nlocal all all reject\nhostssl plus_regression plus_runtime 0.0.0.0/0 scram-sha-256\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n"
	configuration := "listen_addresses = '*'\nport = 5432\nunix_socket_directories = '/run/lindm-plus/socket'\nssl = on\nssl_min_protocol_version = 'TLSv1.3'\nssl_cert_file = '/run/lindm-plus/tls/server.crt'\nssl_key_file = '/run/lindm-plus/tls/server.key'\npassword_encryption = 'scram-sha-256'\nmax_connections = 8\nshared_buffers = '16MB'\nstatement_timeout = '10s'\nlog_statement = 'none'\nlog_min_error_statement = 'panic'\nlog_parameter_max_length = 0\nlog_parameter_max_length_on_error = 0\n"
	for name, content := range map[string]string{"pg_hba.conf": hba, "postgresql.conf": configuration} {
		if err := newFile(filepath.Join(root, name), []byte(content), 0, 0, 0600); err != nil {
			t.Fatal("postgres_plus_cluster_configuration")
		}
	}
	cidfile := filepath.Join(root, "container-id")
	// Register before create: even a timed-out docker create may have recorded
	// its exact ID. Never remove by name, image, label, prefix or enumeration.
	t.Cleanup(func() {
		id, err := os.ReadFile(cidfile)
		if os.IsNotExist(err) {
			return
		}
		if err != nil || !plusExactID(strings.TrimSpace(string(id))) {
			t.Error("postgres_plus_container_cleanup_identity")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := labexec.Run(ctx, labexec.Command{
			Path: "docker", Args: []string{"rm", "--force", "--volumes", strings.TrimSpace(string(id))}, Timeout: 30 * time.Second,
		}); err != nil {
			t.Error("postgres_plus_container_cleanup")
		}
	})
	plusDockerOutput(t, "postgres_plus_container_create", "create", "--pull=never", "--cidfile="+cidfile,
		"--network=bridge", "--publish=127.0.0.1::5432", "--label=lindm.test=installer-postgres-plus",
		"--mount=type=bind,src="+root+",dst=/run/lindm-plus-source,readonly",
		"--tmpfs=/run/lindm-plus:rw,nosuid,noexec,mode=0700", "--tmpfs=/var/lib/postgresql:rw,nosuid,noexec,mode=0700",
		"--entrypoint=/bin/sh", image, "-eu", "-c", plusPostgresEntrypoint)
	id, err := os.ReadFile(cidfile)
	if err != nil || !plusExactID(strings.TrimSpace(string(id))) {
		t.Fatal("postgres_plus_container_identity")
	}
	container := strings.TrimSpace(string(id))
	plusDockerOutput(t, "postgres_plus_container_start", "start", container)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := labexec.Run(ctx, labexec.Command{
			Path: "docker", Args: []string{"exec", "--user=postgres", container, "pg_isready", "--host=/run/lindm-plus/socket", "--username=postgres", "--dbname=postgres"}, Timeout: 5 * time.Second,
		}); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("postgres_plus_cluster_readiness")
		case <-ticker.C:
		}
	}
	address := strings.TrimSpace(plusDockerOutput(t, "postgres_plus_container_port", "port", container, "5432/tcp"))
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("postgres_plus_loopback_binding")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		t.Fatal("postgres_plus_loopback_port")
	}
	return container, port
}

func plusInitializeRole(t *testing.T, container string, password []byte) {
	t.Helper()
	// Hex entropy needs no SQL quoting expansion. SQL and passwords travel only
	// over stdin, never docker argv, environment, logs or failure messages.
	sql := bytes.Join([][]byte{
		[]byte("CREATE ROLE plus_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '"), password,
		[]byte("';\nCREATE DATABASE plus_regression;\nREVOKE ALL ON DATABASE plus_regression FROM PUBLIC;\nGRANT CONNECT ON DATABASE plus_regression TO plus_runtime;\n"),
	}, nil)
	defer clear(sql)
	if err := labexec.Run(t.Context(), labexec.Command{
		Path: "docker", Args: []string{"exec", "--interactive", "--user=postgres", container, "psql", "--no-psqlrc", "--host=/run/lindm-plus/socket", "--username=postgres", "--dbname=postgres", "--set=ON_ERROR_STOP=1"},
		Stdin: bytes.NewReader(sql), Timeout: 15 * time.Second,
	}); err != nil {
		t.Fatal("postgres_plus_role_initialization")
	}
}

func plusConnectionConfig(t *testing.T, root, port string, password []byte) *pgx.ConnConfig {
	t.Helper()
	// pgx v5.11's require_auth parser names the SCRAM family scram-sha-256;
	// scram-sha-256-plus is not an accepted require_auth keyword. Combining the
	// family restriction with channel_binding=require mandates actual PLUS,
	// while rejecting trust, plaintext passwords, MD5 and other auth families.
	// No ambient service/pass/client-key files are allowed to supply credentials.
	cfg, err := pgx.ParseConfig("host=127.0.0.1 port=" + port + " user=plus_runtime dbname=plus_regression sslmode=verify-full sslrootcert=" + filepath.Join(root, "ca.crt") + " sslcert='' sslkey='' passfile=/dev/null channel_binding=require require_auth=scram-sha-256 connect_timeout=5")
	if err != nil {
		t.Fatal("postgres_plus_connection_configuration")
	}
	if cfg.ChannelBinding != "require" || cfg.RequireAuth != "scram-sha-256" || len(cfg.Fallbacks) != 0 || cfg.TLSConfig == nil ||
		cfg.TLSConfig.InsecureSkipVerify || cfg.TLSConfig.ServerName != "127.0.0.1" || cfg.TLSConfig.RootCAs == nil {
		t.Fatal("postgres_plus_connection_policy")
	}
	cfg.TLSConfig.MinVersion = tls.VersionTLS13
	cfg.Password = string(password)
	return cfg
}

func plusExactID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func plusDockerOutput(t *testing.T, category string, args ...string) string {
	t.Helper()
	output := nativeexec.NewBuffer(4096)
	if err := labexec.Run(t.Context(), labexec.Command{
		Path: "docker", Args: args, Stdout: output, Stderr: io.Discard, Timeout: 30 * time.Second,
	}); err != nil || output.Truncated() {
		t.Fatal(category)
	}
	return output.String()
}
