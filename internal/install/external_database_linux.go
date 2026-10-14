// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"
)

// Copy only explicitly named database TLS resources into the corresponding
// identity's custody. Preserve PostgreSQL's host-list syntax and literal '+';
// the maintained checked database loader remains the authoritative validator.
func externalDatabaseCredential(source, directory string, uid, gid int) error {
	data, err := protected(source, true)
	if err != nil {
		return err
	}
	defer clear(data)
	base, query, _ := strings.Cut(strings.TrimSpace(string(data)), "?")
	options, err := url.ParseQuery(strings.ReplaceAll(query, "+", "%2B"))
	if err != nil {
		return errors.New("external database URL has invalid options")
	}
	for _, item := range []struct {
		option, name string
		secret       bool
	}{{"sslrootcert", "external-database-ca.crt", false}, {"sslcert", "external-database-client.crt", false}, {"sslkey", "external-database-client.key", true}} {
		values := options[item.option]
		if len(values) > 1 {
			return errors.New("external database URL repeats a TLS option")
		}
		path := options.Get(item.option)
		if path == "" || (item.option == "sslrootcert" && path == "system") {
			continue
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(source), path)
		}
		content, err := protected(path, item.secret)
		if err != nil {
			return err
		}
		destination := filepath.Join(directory, item.name)
		err = newFile(destination, content, uid, gid, 0600)
		if item.secret {
			clear(content)
		}
		if err != nil {
			return err
		}
		options.Set(item.option, destination)
	}
	encoded := []byte(base + "?" + strings.ReplaceAll(options.Encode(), "+", "%20") + "\n")
	defer clear(encoded)
	return newDatabaseURL(filepath.Join(directory, "database-url"), encoded)
}
