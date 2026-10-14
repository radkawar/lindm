// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"lindm/internal/config"
)

// stagedDatabase retains the fresh target's publication identity separately from
// the temporary document, whose URL and TLS references point into /run.
type stagedDatabase struct {
	document            *config.Document
	configPath, urlFile string
	uid, gid            int
}

// StageDatabaseConfig is the migrator boundary: it never opens application or
// runtime credentials/keys. The migrator's explicit credential validates both
// required schema references in the temporary document.
func StageDatabaseConfig(path string) (*config.Document, func() error, error) {
	target, cleanup, err := stageDatabase(path, true)
	if err != nil {
		return nil, nil, err
	}
	return target.document, cleanup, nil
}

// StageRuntimeDatabaseConfig copies only the runtime database inputs. It never
// reads application signing keys or the separate migrator credential.
func StageRuntimeDatabaseConfig(path string) (*config.Document, func() error, error) {
	target, cleanup, err := stageDatabase(path, false)
	if err != nil {
		return nil, nil, err
	}
	return target.document, cleanup, nil
}

func stageDatabase(path string, migration bool) (*stagedDatabase, func() error, error) {
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("operations: root_required")
	}
	stage, err := os.MkdirTemp("/run", "lindmd-database-*")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() error { return os.RemoveAll(stage) }
	r, err := newResources(path, stage)
	if err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	credential := r.config.GetDatabase().GetUrlFile()
	if migration {
		credential = r.config.GetDatabase().GetMigrationUrlFile()
	}
	if credential == "" {
		return nil, nil, errors.Join(errors.New("operations: explicit_database_credential_required"), cleanup())
	}
	connection, err := r.database(credential)
	if err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	// Capture the original destination and local role ownership before source
	// publication can replace the configuration. Never derive them from an archive.
	stat, ok := r.metadata[path].Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil, errors.Join(errors.New("operations: unavailable_database_config_owner"), cleanup())
	}
	target := &stagedDatabase{configPath: path, urlFile: r.reference(credential), uid: int(stat.Uid), gid: int(stat.Gid)}
	urlPath := filepath.Join(stage, "database-url")
	if err = os.WriteFile(urlPath, []byte(connection), 0600); err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	cloned := proto.CloneOf(r.config)
	cloned.Database.UrlFile = urlPath
	cloned.Database.MigrationUrlFile = nil
	if migration {
		cloned.Database.MigrationUrlFile = &urlPath
	}
	data, err := protojson.Marshal(cloned)
	if err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	configPath := filepath.Join(stage, "server.json")
	if err = os.WriteFile(configPath, data, 0600); err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	document, err := config.Load(configPath)
	if err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	target.document = document
	return target, cleanup, nil
}
