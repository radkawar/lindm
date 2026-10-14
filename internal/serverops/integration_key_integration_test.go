// SPDX-License-Identifier: Apache-2.0

//go:build integration

package serverops

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	"filippo.io/age"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	configv1 "lindm/gen/lindm/config/v1"
	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/identity"
	"lindm/internal/integrations"
	"lindm/internal/integrations/integrationdb"
	"lindm/internal/testdb"
)

// This drill uses the production destination writer and delivery decryptor,
// actual PostgreSQL ciphertext and a real custom dump. It exercises encrypted
// archive/extraction/publication, not the fenced full-host database restore.
func TestIntegrationSecretsSurviveEncryptedArchivePublication(t *testing.T) {
	directory := rootRestoreDirectory(t)
	pool, conn := testdb.Open(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	auth, err := identity.New(ctx, pool, identity.Config{Local: true, PublicURL: "https://admin.example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := auth.Close(); err != nil {
			t.Error(err)
		}
	})
	actor := uuid.New()
	var deployment uuid.UUID
	if err := conn.QueryRow(ctx, "SELECT deployment_id FROM deployment_identity WHERE id").Scan(&deployment); err != nil {
		t.Fatal(err)
	}
	issuer := "urn:lindm:local:" + deployment.String()
	if _, err := conn.Exec(ctx, "INSERT INTO principals(id,issuer,subject,authorization_role,directory_enabled) VALUES($1,$2,$3,'owner',true)", actor, issuer, actor.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "INSERT INTO local_accounts(id,username,role) VALUES($1,$2,'owner')", actor, "backup-"+actor.String()); err != nil {
		t.Fatal(err)
	}
	actorCtx := identity.WithPrincipal(ctx, identity.Principal{ID: actor, Issuer: issuer, Subject: actor.String(), Role: identity.RoleOwner})
	key, freshKey, secret := make([]byte, 32), make([]byte, 32), make([]byte, 32)
	for _, data := range [][]byte{key, freshKey, secret} {
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		defer clear(data)
	}
	if bytes.Equal(key, freshKey) {
		t.Fatal("negative control requires a different key")
	}
	verified := make(chan bool, 16)
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(req.Header.Get("Lindm-Timestamp")))
		mac.Write([]byte("."))
		mac.Write(body)
		signature, decodeErr := hex.DecodeString(strings.TrimPrefix(req.Header.Get("Lindm-Signature"), "v1="))
		valid := decodeErr == nil && hmac.Equal(signature, mac.Sum(nil))
		select {
		case verified <- valid:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()
	roots := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.Certificate().Raw}))
	service, err := integrations.New(pool, auth, key, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateDestination(actorCtx, connect.NewRequest(&integrationsv1.CreateDestinationRequest{RequestId: uuid.NewString(), Config: &integrationsv1.DestinationConfig{DisplayName: "Backup drill", Kind: integrationsv1.DestinationKind_DESTINATION_KIND_WEBHOOK, Endpoint: receiver.URL, PinnedCaPem: roots, Enabled: true}, SigningSecret: secret, Reason: "exercise encrypted backup"}))
	if err != nil {
		t.Fatal(err)
	}
	destination, err := uuid.Parse(created.Msg.Destination.Id)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := integrationdb.New(pool).LoadDeliveryTarget(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored.SecretCiphertext, secret) {
		t.Fatal("destination writer stored plaintext")
	}
	event := uuid.New()
	if _, err := conn.Exec(ctx, "INSERT INTO audit_events(id,action,resource_id,reason) VALUES($1,'device.result',$2,'backup drill')", event, "backup-drill-"+event.String()); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(directory, "server.json")
	keyPath := filepath.Join(directory, "integrations.key")
	runtimeURL := filepath.Join(directory, "database-url")
	migrationConfig := filepath.Join(directory, "migrate", "server.json")
	migrationURL := filepath.Join(directory, "migrate", "database-url")
	cfg := restoreConfigFixture(runtimeURL, false)
	cfg.Integrations = &configv1.IntegrationsConfig{EncryptionKeyFile: keyPath}
	writeRestoreFixture(t, configPath, marshalRestoreFixture(t, cfg), 0, 0)
	writeRestoreFixture(t, keyPath, key, 0, 0)
	connection := []byte("postgresql://fresh:fresh-password@fresh.invalid/fresh?sslmode=verify-full")
	writeRestoreFixture(t, runtimeURL, connection, 0, 0)
	for _, name := range []string{"server.crt", "server.key", "device.crt", "device.key"} {
		writeRestoreFixture(t, filepath.Join(directory, name), []byte("publication custody fixture"), 0, 0)
	}
	stage := filepath.Join(directory, "source")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	r, err := newResources(configPath, stage)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.inventory(r.config.ProtoReflect()); err != nil {
		t.Fatal(err)
	}

	// The fixture loader already checked this owner-only DSN. Never expose its
	// value in argv, diagnostics or a process environment.
	dsn, err := os.ReadFile(os.Getenv("LINDM_TEST_DATABASE_URL_FILE"))
	if err != nil {
		t.Fatal("cannot read protected fixture database reference")
	}
	defer clear(dsn)
	env, err := libpqService(stage, strings.TrimSpace(string(dsn)))
	if err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := conn.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dump := filepath.Join(stage, "database.dump")
	output, err := os.OpenFile(dump, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	dumpErr := runIntegrationDrillDump(t, ctx, pool, schema, env, output)
	closeErr := output.Close()
	if dumpErr != nil {
		t.Fatal(dumpErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	manifest, err := r.manifest(configPath, dump)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Version, manifest.SchemaMinimumRuntime, manifest.SchemaVersions = "0.1.1", 51, []int64{51}
	archiveIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(directory, "backup.tar.age")
	if err := encryptArchive(ctx, archivePath, archiveIdentity.Recipient(), manifest, r, dump); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, key) || bytes.Contains(ciphertext, secret) {
		t.Fatal("plaintext key or secret published")
	}
	identityPath := filepath.Join(directory, "archive-identity")
	passphrase := []byte(hex.EncodeToString(freshKey))
	defer clear(passphrase)
	passphraseRecipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	var protectedIdentity bytes.Buffer
	identityWriter, err := age.Encrypt(&protectedIdentity, passphraseRecipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(identityWriter, archiveIdentity.String()+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := identityWriter.Close(); err != nil {
		t.Fatal(err)
	}
	writeRestoreFixture(t, identityPath, protectedIdentity.Bytes(), 0, 0)
	extractedDir := filepath.Join(directory, "extracted")
	if err := os.Mkdir(extractedDir, 0700); err != nil {
		t.Fatal(err)
	}
	extracted, err := decryptArchive(ctx, archivePath, identityPath, passphrase, extractedDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := runTool(ctx, "pg_restore", []string{"--list", filepath.Join(extractedDir, "database.dump")}, cleanEnvironment(), nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	inventory, _, err := archivedConfiguration(extracted, extractedDir)
	if err != nil {
		t.Fatal(err)
	}

	writeRestoreFixture(t, keyPath, freshKey, 0, 0)
	wrong, err := integrations.New(pool, auth, freshKey, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runIntegrationDrillDeliveries(t, ctx, pool, wrong, destination, event, false)
	select {
	case <-verified:
		t.Fatal("wrong key sent an authenticated webhook")
	default:
	}
	// Publish through the same function as full recovery. Fresh role custody is
	// captured independently of source archive metadata, including key ownership.
	writeRestoreFixture(t, configPath, marshalRestoreFixture(t, cfg), 61001, 61001)
	writeRestoreFixture(t, migrationConfig, marshalRestoreFixture(t, restoreConfigFixture(migrationURL, true)), 61002, 61002)
	writeRestoreFixture(t, migrationURL, connection, 0, 0)
	runtimeTarget, runtimeCleanup, err := stageDatabase(configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtimeCleanup(); err != nil {
			t.Error(err)
		}
	}()
	migrationTarget, migrationCleanup, err := stageDatabase(migrationConfig, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := migrationCleanup(); err != nil {
			t.Error(err)
		}
	}()
	if err := publishRestoredFiles(extracted, inventory, migrationTarget, runtimeTarget); err != nil {
		t.Fatal(err)
	}
	assertRestoreCustody(t, keyPath, 0, 0)
	assertRestoreCustody(t, configPath, 61001, 61001)
	info, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || info.Size() != 32 {
		t.Fatal("restored key has unsafe shape")
	}
	restoredKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(restoredKey)
	if !bytes.Equal(restoredKey, key) || bytes.Equal(restoredKey, freshKey) {
		t.Fatal("restore did not publish exact archived key")
	}
	runtimeResources, err := newResources(configPath, filepath.Join(directory, "restored-runtime-config"))
	if err != nil {
		t.Fatal(err)
	}
	if runtimeResources.config.GetIntegrations().GetEncryptionKeyFile() != keyPath {
		t.Fatal("persistent key reference changed")
	}
	migrationResources, err := newResources(migrationConfig, filepath.Join(directory, "restored-migration-config"))
	if err != nil {
		t.Fatal(err)
	}
	if migrationResources.config.GetIntegrations() != nil {
		t.Fatal("migrator gained integration secret access")
	}
	after, err := integrationdb.New(pool).LoadDeliveryTarget(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.SecretCiphertext, after.SecretCiphertext) {
		t.Fatal("drill replaced stored ciphertext")
	}
	if _, err := conn.Exec(ctx, "UPDATE integration_deliveries SET next_attempt_at=clock_timestamp() WHERE destination_id=$1 AND status=1", destination); err != nil {
		t.Fatal(err)
	}
	recovered, err := integrations.New(pool, auth, restoredKey, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runIntegrationDrillDeliveries(t, ctx, pool, recovered, destination, event, true)
	select {
	case valid := <-verified:
		if !valid {
			t.Fatal("restored secret produced invalid webhook signature")
		}
	case <-ctx.Done():
		t.Fatal("restored key did not deliver authenticated webhook")
	}
}

func runIntegrationDrillDeliveries(t *testing.T, ctx context.Context, pool *pgxpool.Pool, service *integrations.Service, destination, event uuid.UUID, success bool) {
	t.Helper()
	workerCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- service.RunDeliveries(workerCtx) }()
	defer func() {
		stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var status int32
		var reason string
		if err := pool.QueryRow(ctx, "SELECT status,last_error FROM integration_deliveries WHERE destination_id=$1 AND event_id=$2", destination, event).Scan(&status, &reason); err != nil {
			t.Fatal(err)
		}
		if success && status == 3 {
			return
		}
		if !success && reason == "destination_secret_unreadable" {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("integration delivery did not reach expected outcome")
		case <-ticker.C:
		}
	}
}

// Opt-in diagnostics remain in a caller-selected private file, never test output.
// This is an integration-test path, not a product override of redacted tooling.
func runIntegrationDrillDump(t *testing.T, ctx context.Context, pool *pgxpool.Pool, schema string, env []string, output io.Writer) error {
	t.Helper()
	args := []string{"--dbname=service=lindm-backup", "--schema=" + schema, "--format=custom", "--no-owner", "--no-acl", "--no-password"}
	path := os.Getenv("LINDM_TEST_PG_DUMP_DIAGNOSTIC")
	if path == "" {
		return runTool(ctx, "pg_dump", args, env, nil, output)
	}
	diagnostic, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("private dump diagnostic could not be created")
	}
	defer func() {
		if err := diagnostic.Close(); err != nil {
			t.Error("private dump diagnostic could not be closed")
		}
	}()
	var role, version, address string
	var port int
	metadataErr := pool.QueryRow(ctx, "SELECT current_user,current_setting('server_version'),COALESCE(inet_server_addr()::text,'local-socket'),COALESCE(inet_server_port(),0)").Scan(&role, &version, &address, &port)
	_, _ = fmt.Fprintf(diagnostic, "server_version=%s role=%s address=%s port=%d metadata_error=%v context_before=%v\n", version, role, address, port, metadataErr, ctx.Err())
	client := exec.CommandContext(ctx, "pg_dump", "--version")
	client.Env, client.Stdout, client.Stderr = env, diagnostic, diagnostic
	_ = client.Run()
	started := time.Now()
	dumpErr := runToolWithStderr(ctx, "pg_dump", args, env, nil, output, diagnostic)
	_, _ = fmt.Fprintf(diagnostic, "\ndump_duration=%s dump_error=%v context_after=%v\n", time.Since(started), dumpErr, ctx.Err())
	if dumpErr != nil {
		return dumpErr
	}
	return nil
}
