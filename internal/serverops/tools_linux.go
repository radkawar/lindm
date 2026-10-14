// SPDX-License-Identifier: Apache-2.0

package serverops

import (
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

func dumpDatabase(ctx context.Context, stage, connection string) (path string, err error) {
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
	err = runTool(ctx, "pg_dump", []string{"--dbname=service=lindm-backup", "--format=custom", "--no-password", "--no-owner", "--no-acl"}, env, nil, &boundedWriter{file, maxArchive})
	return path, err
}
