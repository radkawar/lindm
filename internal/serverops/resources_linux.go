// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
)

const maxResource = 1 << 20
const maxArchive = int64(128 << 30)

type resourceSet struct {
	config              *configv1.ServerConfig
	files               map[string]string
	owners              map[uint32]bool
	metadata            map[string]os.FileInfo
	databaseCredentials map[string]bool
	totalBytes          int64
	archived            bool
	base                string
	stage               string
}

func newResources(path, stage string) (*resourceSet, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("operations: clean absolute config required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("operations: private configuration required")
	}
	r := &resourceSet{files: map[string]string{}, metadata: map[string]os.FileInfo{}, owners: map[uint32]bool{0: true, stat.Uid: true}, base: filepath.Dir(path), stage: stage}
	if err = r.copy(path); err != nil {
		return nil, err
	}
	document, err := config.Load(r.files[path])
	if err != nil {
		return nil, errors.New("operations: invalid_native_configuration")
	}
	r.config = document.Proto
	r.databaseCredentials = map[string]bool{}
	for _, credential := range []string{r.config.GetDatabase().GetUrlFile(), r.config.GetDatabase().GetMigrationUrlFile()} {
		if credential != "" {
			r.databaseCredentials[r.reference(credential)] = true
		}
	}
	return r, nil
}

// open pins every ancestor without following symlinks. A configured service
// owner is admitted only here for root's backup; runtime loader policy is unchanged.
func (r *resourceSet) open(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("operations: invalid resource path")
	}
	if r.archived && os.Geteuid() != 0 {
		file, _, err := openOperationFile(path, maxArchive, true)
		return file, err
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		flags := unix.O_PATH | unix.O_DIRECTORY
		if i == len(parts)-1 {
			flags = unix.O_RDONLY
		}
		next, openErr := unix.Openat(fd, part, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		closeErr := unix.Close(fd)
		if openErr != nil {
			return nil, errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			return nil, errors.Join(closeErr, unix.Close(next))
		}
		fd = next
		var stat unix.Stat_t
		if err = unix.Fstat(fd, &stat); err != nil {
			return nil, errors.Join(err, unix.Close(fd))
		}
		if !r.owners[stat.Uid] || stat.Mode&0022 != 0 {
			return nil, errors.Join(errors.New("operations: unsafe resource custody"), unix.Close(fd))
		}
		if r.databaseCredentials[path] && (stat.Uid != 0 || (i == len(parts)-1 && (stat.Gid != 0 || stat.Mode&07777 != 0600))) {
			return nil, errors.Join(errors.New("operations: root_private_database_credential_required"), unix.Close(fd))
		}
		if i == len(parts)-1 && stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return nil, errors.Join(errors.New("operations: regular resource required"), unix.Close(fd))
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func (r *resourceSet) read(path string, limit int64) (_ []byte, err error) {
	if staged, ok := r.files[path]; ok {
		path = staged
	} else if r.archived {
		return nil, errors.New("operations: incomplete_archived_reference")
	}
	file, err := r.open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("operations: resource size exceeded")
	}
	return data, nil
}

func (r *resourceSet) reference(path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(r.base, path)
}

func (r *resourceSet) copy(path string) (err error) {
	if _, ok := r.files[path]; ok {
		return nil
	}
	if r.archived {
		return errors.New("operations: incomplete_archived_reference")
	}
	input, err := r.open(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxArchive-r.totalBytes || len(r.files) >= 65536 {
		return errors.New("operations: backup_inventory_capacity")
	}
	target := filepath.Join(r.stage, "files", strings.TrimPrefix(path, "/"))
	if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(output, io.LimitReader(input, info.Size()+1))
	if err = errors.Join(copyErr, output.Close()); err != nil {
		return err
	}
	after, err := input.Stat()
	if err != nil {
		return err
	}
	beforeStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("operations: missing_resource_custody")
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("operations: missing_resource_custody")
	}
	if written != info.Size() || beforeStat.Mtim != afterStat.Mtim || beforeStat.Ctim != afterStat.Ctim || beforeStat.Dev != afterStat.Dev || beforeStat.Ino != afterStat.Ino {
		return errors.New("operations: resource_changed_during_backup")
	}
	r.files[path] = target
	r.metadata[path] = info
	r.totalBytes += written
	return nil
}

func (r *resourceSet) rewrite(message protoreflect.Message) error {
	var failure error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Kind() == protoreflect.MessageKind {
			if field.IsList() {
				list := value.List()
				for i := range list.Len() {
					if err := r.rewrite(list.Get(i).Message()); err != nil {
						failure = err
						return false
					}
				}
			} else if !field.IsMap() {
				failure = r.rewrite(value.Message())
			}
			return failure == nil
		}
		if field.Kind() != protoreflect.StringKind || !strings.HasSuffix(string(field.Name()), "_file") || value.String() == "" {
			return true
		}
		original := r.reference(value.String())
		if err := r.copy(original); err != nil {
			failure = err
			return false
		}
		message.Set(field, protoreflect.ValueOfString(r.files[original]))
		return true
	})
	return failure
}

func (r *resourceSet) database(file string) (string, error) {
	original := r.reference(file)
	if r.databaseCredentials == nil {
		r.databaseCredentials = map[string]bool{}
	}
	r.databaseCredentials[original] = true
	data, err := r.read(original, maxResource)
	defer clear(data)
	if err != nil {
		return "", err
	}
	connection := strings.TrimSpace(string(data))
	u, err := databaseURL(connection)
	if err != nil {
		return "", err
	}
	options, err := url.ParseQuery(u.RawQuery)
	if err != nil || options.Get("sslmode") != "verify-full" {
		return "", errors.New("operations: database requires verify-full")
	}
	for _, name := range []string{"sslrootcert", "sslcert", "sslkey"} {
		path := options.Get(name)
		if path == "" || path == "system" {
			continue
		}
		original := r.reference(path)
		if err = r.copy(original); err != nil {
			return "", err
		}
		options.Set(name, r.files[original])
	}
	base, _, _ := strings.Cut(connection, "?")
	return base + "?" + strings.ReplaceAll(options.Encode(), "+", "%20"), nil
}

func (r *resourceSet) validate(path string) (*config.Document, error) {
	cloned := proto.CloneOf(r.config)
	if err := r.rewrite(cloned.ProtoReflect()); err != nil {
		return nil, err
	}
	for _, migration := range []bool{false, true} {
		source := r.config.GetDatabase().GetUrlFile()
		if migration {
			source = r.config.GetDatabase().GetMigrationUrlFile()
		}
		if source == "" {
			continue
		}
		connection, err := r.database(source)
		if err != nil {
			return nil, err
		}
		name := filepath.Join(r.stage, "validated-runtime-url")
		if migration {
			name = filepath.Join(r.stage, "validated-migration-url")
		}
		if err = os.WriteFile(name, []byte(connection), 0600); err != nil {
			return nil, err
		}
		if migration {
			cloned.GetDatabase().MigrationUrlFile = &name
		} else {
			cloned.GetDatabase().UrlFile = name
		}
	}
	data, err := protojson.Marshal(cloned)
	if err != nil {
		return nil, err
	}
	validated := filepath.Join(r.stage, "validated.json")
	if err = os.WriteFile(validated, data, 0600); err != nil {
		return nil, err
	}
	doc, err := config.Load(validated)
	if err != nil {
		return nil, fmt.Errorf("operations: validate configuration: %w", err)
	}
	return doc, nil
}
