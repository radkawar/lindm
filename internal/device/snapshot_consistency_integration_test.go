//go:build integration

package device

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lindm/internal/device/inventory"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/gen/lindm/device/v1/devicev1connect"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestGetDeviceUsesOneDatabaseSnapshot(t *testing.T) {
	for _, change := range []string{"publication", "host"} {
		t.Run(change, func(t *testing.T) {
			f := newEnrolled(t, 0)
			f.publishPackages(t, 1, "original")
			if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(hostObservation(f.generation, 1, "original"))); err != nil {
				t.Fatal(err)
			}
			f.now = f.now.Add(inventory.SnapshotAttemptInterval)
			var replacement *devicev1.PackageSnapshotManifest
			if change == "publication" {
				raw := packageBatch(t, &inventoryv1.Package{Name: "replacement", Version: "1", Manager: "apt"})
				replacement = snapshotManifest(t, f.generation, 2, f.now, [][]byte{raw})
				if _, err := f.begin(t, replacement, 1); err != nil {
					t.Fatal(err)
				}
				if _, err := f.put(t, replacement.GetSnapshotId(), 0, raw, 1); err != nil {
					t.Fatal(err)
				}
			}
			before, err := f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
			if err != nil {
				t.Fatal(err)
			}

			// Block the actual second component query, after the device projection
			// has been read. No production test hook or timing-based interleaving.
			lock, err := f.conn.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := lock.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
					t.Error(err)
				}
			})
			if _, err := lock.Exec(f.ctx, `LOCK TABLE host_observations IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			type detailResult struct {
				response *connect.Response[adminv1.GetDeviceResponse]
				err      error
			}
			result := make(chan detailResult, 1)
			go func() {
				response, err := f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
				result <- detailResult{response: response, err: err}
			}()
			ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
			defer cancel()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				var waiting bool
				if err := f.svc.Pool.QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM pg_stat_activity
					WHERE $1::integer = ANY(pg_blocking_pids(pid))
					AND query LIKE '-- name: GetHostObservation %'
				)`, int32(f.conn.PgConn().PID())).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case got := <-result:
					t.Fatalf("detail returned before reaching the blocked host query: %v", got.err)
				case <-ticker.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if change == "publication" {
				if _, err := f.commit(t, replacement, 1); err != nil {
					t.Fatal(err)
				}
			} else {
				// Publish the host observation and its projections atomically on the
				// lock-owning connection, while the reader waits at the boundary.
				if _, err := lock.Exec(ctx, `UPDATE host_observations SET sequence = 2, hostname_value = 'replacement' WHERE generation_id = $1`, f.principal.GenerationID); err != nil {
					t.Fatal(err)
				}
				if _, err := lock.Exec(ctx, `UPDATE enrollment_generations SET host_sequence = 2 WHERE id = $1`, f.principal.GenerationID); err != nil {
					t.Fatal(err)
				}
				if _, err := lock.Exec(ctx, `UPDATE devices SET hostname = 'replacement' WHERE id = $1`, f.principal.DeviceID); err != nil {
					t.Fatal(err)
				}
			}
			if err := lock.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-result:
				if got.err != nil {
					t.Fatal(got.err)
				}
				if !proto.Equal(got.response.Msg, before.Msg) {
					t.Fatalf("detail mixed database snapshots after concurrent %s:\nbefore: %s\nafter: %s", change, before.Msg, got.response.Msg)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			after, err := f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
			if err != nil {
				t.Fatal(err)
			}
			if proto.Equal(after.Msg, before.Msg) {
				t.Fatal("concurrent update was not committed")
			}
		})
	}
}

func TestPutPackageBatchJSONAcceptsMaximumDecodedPayload(t *testing.T) {
	f := newEnrolled(t, 0)
	packages := make([]*inventoryv1.Package, 384)
	for i := range packages {
		packages[i] = &inventoryv1.Package{Name: "p", Manager: "m", Version: strings.Repeat("v", 2036)}
	}
	raw := packageBatch(t, packages...)
	if len(raw) != core.MaxBatchBytes {
		t.Fatalf("boundary fixture has %d bytes, want %d", len(raw), core.MaxBatchBytes)
	}
	manifest := snapshotManifest(t, f.generation, 1, f.now, [][]byte{raw})
	leaf := parseCertPEM(t, activeCertificatePEM(t, f.ctx, f.conn, f.principal.DeviceID))
	roots := x509.NewCertPool()
	roots.AddCert(f.svc.CA)
	path, handler := f.svc.DeviceHandler()
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	transport, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("test server did not provide an HTTP transport")
	}
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: f.key}}
	client := devicev1connect.NewDeviceServiceClient(server.Client(), server.URL, connect.WithProtoJSON())
	if _, err := client.BeginPackageSnapshot(f.ctx, connect.NewRequest(&devicev1.BeginPackageSnapshotRequest{
		EnrollmentGeneration: f.generation, SessionEpoch: 1, Manifest: manifest,
	})); err != nil {
		t.Fatal(err)
	}
	request := &devicev1.PutPackageBatchRequest{
		EnrollmentGeneration: f.generation, SessionEpoch: 1, SnapshotId: manifest.GetSnapshotId(), Batch: raw,
	}
	encoded, err := protojson.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) <= core.MaxMessageBytes {
		t.Fatalf("JSON fixture does not exercise the base64 envelope boundary: %d", len(encoded))
	}
	if _, err := client.PutPackageBatch(f.ctx, connect.NewRequest(request)); err != nil {
		t.Fatalf("valid %d-byte decoded batch (%d-byte JSON request) rejected: %v", len(raw), len(encoded), err)
	}
	if _, err := client.CommitPackageSnapshot(f.ctx, connect.NewRequest(&devicev1.CommitPackageSnapshotRequest{
		EnrollmentGeneration: f.generation, SessionEpoch: 1, Manifest: manifest,
	})); err != nil {
		t.Fatal(err)
	}
	if got := publishedSequence(t, f); got != 1 {
		t.Fatalf("uploaded maximum batch did not publish: sequence=%d", got)
	}
	request.Batch = append(raw, 0)
	if _, err := client.PutPackageBatch(f.ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("decoded payload limit was not preserved: %v", err)
	}
}
