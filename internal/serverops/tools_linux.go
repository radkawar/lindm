// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/internal/platform"
)

// runTool never relays subprocess diagnostics: PostgreSQL and archive tools can
// include URLs, row values and private paths in their error output.
func runTool(ctx context.Context, tool string, args []string, env []string, stdin io.Reader, stdout io.Writer) error {
	return runToolWithStderr(ctx, tool, args, env, stdin, stdout, io.Discard)
}

// The diagnostic sink is internal; product callers always discard raw stderr.
func runToolWithStderr(ctx context.Context, tool string, args []string, env []string, stdin io.Reader, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, tool, args...)
	command.Env = env
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	command.WaitDelay = 5 * time.Second
	if err := command.Run(); err != nil {
		if cause := ctx.Err(); cause != nil {
			return fmt.Errorf("operations: %s_failed: %w", filepath.Base(tool), cause)
		}
		return fmt.Errorf("operations: %s_failed", filepath.Base(tool))
	}
	return nil
}

func cleanEnvironment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
}

// libpqService keeps credential values in a private file. Only its nonsecret
// pathname enters a subprocess environment. The main configuration loader never
// sees PG* settings. An explicit service prevents home-directory fallback.
func libpqService(stage, connection string) ([]string, error) {
	u, err := databaseURL(connection)
	if err != nil {
		return nil, err
	}
	parsed, err := pgxpool.ParseConfig(connection)
	if err != nil {
		return nil, errors.New("operations: invalid database URL")
	}
	password, _ := u.User.Password()
	var hosts, ports []string
	addHost := func(host string, port uint16) {
		for i, prior := range hosts {
			if prior == host && ports[i] == strconv.Itoa(int(port)) {
				return
			}
		}
		hosts = append(hosts, host)
		ports = append(ports, strconv.Itoa(int(port)))
	}
	addHost(parsed.ConnConfig.Host, parsed.ConnConfig.Port)
	for _, fallback := range parsed.ConnConfig.Fallbacks {
		addHost(fallback.Host, fallback.Port)
	}
	passfile := filepath.Join(stage, "pg-password")
	if strings.ContainsAny(password, "\r\n\x00") {
		return nil, errors.New("operations: libpq_password_file_cannot_represent_credential")
	}
	escape := strings.NewReplacer("\\", "\\\\", ":", "\\:")
	pass := "*:*:" + escape.Replace(parsed.ConnConfig.Database) + ":" + escape.Replace(u.User.Username()) + ":" + escape.Replace(password) + "\n"
	if err = os.WriteFile(passfile, []byte(pass), 0600); err != nil {
		return nil, err
	}
	values := map[string]string{"host": strings.Join(hosts, ","), "port": strings.Join(ports, ","), "user": u.User.Username(), "passfile": passfile, "dbname": parsed.ConnConfig.Database, "sslmode": "verify-full"}
	for key, entries := range u.Query() {
		if len(entries) != 1 {
			return nil, errors.New("operations: repeated database option")
		}
		values[key] = entries[0]
	}
	// Native dumps and restores must use the same calendar arithmetic as the
	// application's UTC sessions, independently of the cluster's local zone.
	values["options"] = "-c timezone=UTC"
	var keys []string
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var text strings.Builder
	text.WriteString("[lindm-backup]\n")
	for _, key := range keys {
		value := values[key]
		if strings.ContainsAny(value, "\r\n\x00") || strings.ContainsAny(key, "=\r\n") {
			return nil, errors.New("operations: invalid libpq service value")
		}
		if key == "port" && value == "" {
			continue
		}
		text.WriteString(key + "=" + value + "\n")
	}
	path := filepath.Join(stage, "pg-service.conf")
	if err = os.WriteFile(path, []byte(text.String()), 0600); err != nil {
		return nil, err
	}
	return append(cleanEnvironment(), "PGSERVICEFILE="+path, "PGPASSFILE=/nonexistent"), nil
}

// databaseURL delegates host-list parsing to pgx while using a placeholder host
// only for URI user/database/query decoding; net/url rejects libpq host lists.
func databaseURL(connection string) (*url.URL, error) {
	base, query, _ := strings.Cut(connection, "?")
	scheme, rest, ok := strings.Cut(base, "://")
	if !ok || (scheme != "postgres" && scheme != "postgresql") {
		return nil, errors.New("operations: invalid database URL")
	}
	authority, database, ok := strings.Cut(rest, "/")
	if !ok || database == "" {
		return nil, errors.New("operations: invalid database URL")
	}
	userinfo, hosts, ok := strings.Cut(authority, "@")
	if !ok || hosts == "" {
		return nil, errors.New("operations: invalid database URL")
	}
	u, err := url.Parse(scheme + "://" + userinfo + "@localhost/" + database + "?" + query)
	if err != nil || u.User == nil || u.User.Username() == "" {
		return nil, errors.New("operations: invalid database URL")
	}
	return u, nil
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, errors.New("operations: output_size_exceeded")
	}
	n, err := w.writer.Write(data)
	w.remaining -= int64(n)
	return n, err
}

// Resolve once and execute that same path after checking its public version.
// Backup clients must match exactly; pg_dump's backwards compatibility does not
// establish the authentication and recovery contract.
func postgreSQLTool(ctx context.Context, tool string, major int) (string, error) {
	path, err := exec.LookPath(tool)
	if err != nil {
		return "", fmt.Errorf("operations: %s_unavailable", tool)
	}
	var output bytes.Buffer
	if err := runTool(ctx, path, []string{"--version"}, cleanEnvironment(), nil, &boundedWriter{&output, 4096}); err != nil {
		return "", err
	}
	if err := checkPostgreSQLToolVersion(tool, output.String(), major); err != nil {
		return "", err
	}
	return path, nil
}

func postgreSQLMajor(version string) int {
	major, _, _ := strings.Cut(version, ".")
	value, err := strconv.Atoi(major)
	if err != nil {
		return 0
	}
	return value
}

func checkPostgreSQLToolVersion(tool, version string, major int) error {
	fields := strings.Fields(version)
	if !platform.PostgreSQLMajorSupported(major) || len(fields) < 3 || fields[0] != tool ||
		fields[1] != "(PostgreSQL)" || postgreSQLMajor(fields[2]) != major {
		return fmt.Errorf("operations: %s_major_mismatch_require_PostgreSQL_%d", tool, major)
	}
	return nil
}

func databaseMajor(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var version int64
	if err := pool.QueryRow(ctx, "SELECT current_setting('server_version_num')::bigint").Scan(&version); err != nil {
		return 0, errors.New("operations: database_version_unavailable")
	}
	major := int(version / 10000)
	if !platform.PostgreSQLMajorSupported(major) {
		return 0, errors.New("operations: database_requires_PostgreSQL_16_17_or_18")
	}
	return major, nil
}

// pg_restore's public listing includes both the source server and dump client
// versions. Validate them without contacting a database so offline drills retain
// the same exact-major contract as a live restore.
func archivePostgreSQLMajor(listing string) (int, error) {
	var server, dump int
	var serverSeen, dumpSeen bool
	for line := range strings.SplitSeq(listing, "\n") {
		header, ok := strings.CutPrefix(line, ";")
		if !ok {
			continue
		}
		header = strings.TrimSpace(header)
		if value, ok := strings.CutPrefix(header, "Dumped from database version: "); ok {
			if serverSeen {
				return 0, errors.New("operations: invalid_database_archive_versions")
			}
			serverSeen = true
			server = postgreSQLMajor(strings.TrimSpace(value))
		}
		if value, ok := strings.CutPrefix(header, "Dumped by pg_dump version: "); ok {
			if dumpSeen {
				return 0, errors.New("operations: invalid_database_archive_versions")
			}
			dumpSeen = true
			dump = postgreSQLMajor(strings.TrimSpace(value))
		}
	}
	if !platform.PostgreSQLMajorSupported(server) || server != dump {
		return 0, errors.New("operations: database_archive_requires_matching_PostgreSQL_16_17_or_18")
	}
	return server, nil
}

// Keep only the bounded header, not the potentially large table-of-contents.
// The real parser still consumes the complete archive.
type archiveHeaderWriter struct {
	header []byte
}

func (w *archiveHeaderWriter) Write(data []byte) (int, error) {
	if remaining := 4096 - len(w.header); remaining > 0 {
		w.header = append(w.header, data[:min(len(data), remaining)]...)
	}
	return len(data), nil
}

func checkDatabaseArchive(ctx context.Context, path string) (tool string, major int, err error) {
	tool, err = exec.LookPath("pg_restore")
	if err != nil {
		return "", 0, errors.New("operations: pg_restore_unavailable")
	}
	var header archiveHeaderWriter
	if err = runTool(ctx, tool, []string{"--list", path}, cleanEnvironment(), nil, &header); err != nil {
		return "", 0, err
	}
	major, err = archivePostgreSQLMajor(string(header.header))
	if err != nil {
		return "", 0, err
	}
	var version bytes.Buffer
	if err = runTool(ctx, tool, []string{"--version"}, cleanEnvironment(), nil, &boundedWriter{&version, 4096}); err != nil {
		return "", 0, err
	}
	if err = checkPostgreSQLToolVersion("pg_restore", version.String(), major); err != nil {
		return "", 0, err
	}
	return tool, major, nil
}

func dumpDatabase(ctx context.Context, stage, connection string, major int) (path string, err error) {
	tool, err := postgreSQLTool(ctx, "pg_dump", major)
	if err != nil {
		return "", err
	}
	if _, err = postgreSQLTool(ctx, "pg_restore", major); err != nil {
		return "", err
	}
	env, err := libpqService(stage, connection)
	if err != nil {
		return "", err
	}
	path = filepath.Join(stage, "database.dump")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	err = runTool(ctx, tool, []string{"--dbname=service=lindm-backup", "--format=custom", "--no-password", "--no-owner", "--no-acl"}, env, nil, &boundedWriter{file, maxArchive})
	if err != nil {
		return "", err
	}
	_, archiveMajor, err := checkDatabaseArchive(ctx, path)
	if err != nil {
		return "", err
	}
	if archiveMajor != major {
		return "", errors.New("operations: dump_database_archive_major_mismatch")
	}
	return path, err
}
