package deploylab

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/html"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/gen/lindm/admin/v1/adminv1connect"
)

func proveHTTPS(ctx context.Context, origin string, ca []byte, result *ComposeResult) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("deployment fixture has no TLS trust root")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	ready, stop := context.WithTimeout(ctx, time.Minute)
	defer stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := getHTTPS(ready, client, origin+"/readyz", http.StatusNoContent)
		if err == nil {
			break
		}
		select {
		case <-ready.Done():
			return fmt.Errorf("HTTPS readiness: %w", errors.Join(ready.Err(), err))
		case <-ticker.C:
		}
	}
	result.HTTPSReady = true
	if _, err := getHTTPS(ctx, client, origin+"/healthz", http.StatusNoContent); err != nil {
		return fmt.Errorf("HTTPS health: %w", err)
	}
	result.HTTPSHealth = true
	index, err := getHTTPS(ctx, client, origin+"/", http.StatusOK)
	if err != nil {
		return fmt.Errorf("embedded console HTML: %w", err)
	}
	asset, err := consoleAsset(index)
	if err != nil {
		return err
	}
	if _, err := getHTTPS(ctx, client, origin+asset, http.StatusOK); err != nil {
		return fmt.Errorf("embedded console JavaScript: %w", err)
	}
	result.EmbeddedConsole = true
	admin := adminv1connect.NewAdminServiceClient(client, origin)
	_, err = admin.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 1}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		return fmt.Errorf("protected RPC must deny anonymous access with unauthenticated, got %s", connect.CodeOf(err))
	}
	result.ProtectedRPCDenied = true
	return nil
}

func getHTTPS(ctx context.Context, client *http.Client, endpoint string, status int) (_ []byte, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, response.Body.Close()) }()
	if response.StatusCode != status {
		return nil, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || len(response.TLS.VerifiedChains) == 0 {
		return nil, errors.New("HTTPS probe did not verify TLS 1.3")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 8<<20 {
		return nil, errors.New("deployment HTTPS response exceeds 8 MiB")
	}
	return body, nil
}

func consoleAsset(index []byte) (string, error) {
	tokens := html.NewTokenizer(bytes.NewReader(index))
	for {
		switch tokens.Next() {
		case html.ErrorToken:
			if err := tokens.Err(); err != io.EOF {
				return "", err
			}
			return "", errors.New("embedded console has no built JavaScript asset")
		case html.StartTagToken:
			token := tokens.Token()
			if token.Data != "script" {
				continue
			}
			for _, attr := range token.Attr {
				if attr.Key == "src" && strings.HasPrefix(attr.Val, "/assets/") && strings.HasSuffix(attr.Val, ".js") {
					return attr.Val, nil
				}
			}
		}
	}
}

func (r *composeRun) proveIsolation(ctx context.Context, uid, gid int) error {
	container := new(commandOutput)
	if err := r.compose(ctx, "find owned server container", container, "ps", "--quiet", "lindmd"); err != nil {
		return err
	}
	id := strings.TrimSpace(container.String())
	if id == "" || strings.ContainsAny(id, "\r\n\t ") {
		return errors.New("owned server container identity is missing or ambiguous")
	}
	output := new(commandOutput)
	if err := r.command(ctx, "inspect runtime isolation", output, "docker", "inspect", id); err != nil {
		return err
	}
	var inspected []struct {
		Config struct {
			User string
		}
		HostConfig struct {
			ReadonlyRootfs bool
			CapDrop        []string
			SecurityOpt    []string
			Memory         int64
			MemorySwap     int64
			NanoCpus       int64
			PidsLimit      int64
			Ulimits        []struct {
				Name string
				Soft int64
				Hard int64
			}
		}
		Mounts []struct {
			Destination string
			RW          bool
		}
	}
	if err := json.Unmarshal(output.Bytes(), &inspected); err != nil {
		return fmt.Errorf("decode runtime isolation: %w", err)
	}
	if len(inspected) != 1 {
		return errors.New("runtime isolation requires one owned container")
	}
	server := inspected[0]
	host := server.HostConfig
	if server.Config.User != strconv.Itoa(uid)+":"+strconv.Itoa(gid) || !host.ReadonlyRootfs || !slices.Contains(host.CapDrop, "ALL") || !slices.Contains(host.SecurityOpt, "no-new-privileges:true") || host.Memory <= 0 || host.MemorySwap != host.Memory || host.NanoCpus <= 0 || host.PidsLimit <= 0 {
		return errors.New("runtime container is missing nonroot, read-only, capability or resource isolation")
	}
	coreDisabled := false
	for _, limit := range host.Ulimits {
		if limit.Name == "core" && limit.Soft == 0 && limit.Hard == 0 {
			coreDisabled = true
		}
	}
	if !coreDisabled {
		return errors.New("runtime container must disable core dumps")
	}
	allowed := map[string]bool{
		"/etc/lindm/server.json":      false,
		"/etc/lindm/database-url":     false,
		"/etc/lindm/transport-ca.crt": false,
		"/etc/lindm/server.crt":       false,
		"/etc/lindm/server.key":       false,
		"/etc/lindm/device-ca.crt":    false,
		"/etc/lindm/device-ca.key":    false,
	}
	if len(server.Mounts) != len(allowed) {
		return errors.New("runtime mounts differ from the least-privilege allowlist")
	}
	for _, mount := range server.Mounts {
		seen, ok := allowed[mount.Destination]
		if !ok || seen || mount.RW {
			return errors.New("runtime has an unexpected, duplicate or writable secret mount")
		}
		allowed[mount.Destination] = true
	}
	return nil
}

func (r *composeRun) proveDatabase(ctx context.Context) error {
	// Catalog checks supplement the successful verify-full client startup: the
	// actual runtime connection must be TLS 1.3 and its role cannot perform DDL
	// or assume the migrator. No URL, password or application row is printed.
	const query = `SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
AND NOT rolreplication AND NOT rolbypassrls
AND NOT has_database_privilege('lindm_runtime', 'lindm', 'CREATE')
AND NOT has_schema_privilege('lindm_runtime', 'public', 'CREATE')
AND NOT pg_has_role('lindm_runtime', 'lindm_migrator', 'MEMBER')
AND has_table_privilege('lindm_runtime', 'public.goose_db_version', 'SELECT')
AND NOT has_table_privilege('lindm_runtime', 'public.goose_db_version', 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
AND NOT coalesce(has_sequence_privilege('lindm_runtime', pg_get_serial_sequence('public.goose_db_version','id'), 'USAGE,SELECT,UPDATE'), false)
AND EXISTS (SELECT 1 FROM pg_stat_activity a JOIN pg_stat_ssl s USING (pid)
 WHERE a.usename = 'lindm_runtime' AND s.ssl AND s.version = 'TLSv1.3')
FROM pg_roles WHERE rolname = 'lindm_runtime'`
	output := new(commandOutput)
	if err := r.compose(ctx, "prove database TLS and role separation", output, "exec", "-T", "--user", "postgres", "postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "lindm", "-At", "-c", query); err != nil {
		return err
	}
	if strings.TrimSpace(output.String()) != "t" {
		return errors.New("database runtime TLS or role separation proof failed")
	}
	return nil
}
