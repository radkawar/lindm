//go:build linux

package accountprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/custody"
)

type localDB struct {
	users, groups, shadow, gshadow map[string][]string
	// shadowGroups is whether /etc/gshadow exists. shadow's tools maintain it
	// only when present; openSUSE (Tumbleweed) ships none.
	shadowGroups bool
	revision     []byte
}

// nativeRun executes one fixed tool. stdin carries the only secret input any
// shadow tool receives (chpasswd --encrypted); it never enters argv or env.
type nativeRun func(ctx context.Context, stdin []byte, path string, args ...string) ([]byte, error)

// runNative keeps the historical policy that any shadow-utils stderr fails the
// command: diagnostics name users and line numbers, never the stdin token, so
// the sanitized first line is surfaced for the administrator. The only stderr
// tolerated is pacman's notice that a configured sync database was never
// downloaded: the local -Qo query does not read it.
func runNative(ctx context.Context, stdin []byte, path string, args ...string) ([]byte, error) {
	result, err := nativeexec.Run(ctx, nativeexec.Command{Path: path, Args: args, Stdin: stdin, Timeout: 20 * time.Second, StdoutLimit: 1 << 20, StderrLimit: 1 << 20})
	stderr := result.Stderr
	if path == pacmanPath {
		stderr = withoutMissingSyncDatabaseNotices(stderr)
	}
	if len(stderr) != 0 {
		return nil, fmt.Errorf("accountprovider: native diagnostic from %s: %s", filepath.Base(path), result.Diagnostic())
	}
	if err != nil {
		return nil, err
	}
	return result.Stdout, nil
}

const pacmanPath = "/usr/bin/pacman"

// withoutMissingSyncDatabaseNotices drops pacman's exact per-repository
// "database file for '<repo>' does not exist" warnings. An offline install
// (Omarchy 4.0.4) ships no /var/lib/pacman/sync/*.db, so every query printed
// them and the shadow backend version lookup failed. Any other line remains.
func withoutMissingSyncDatabaseNotices(stderr []byte) []byte {
	var kept []byte
	for line := range bytes.Lines(stderr) {
		repo, ok := bytes.CutPrefix(bytes.TrimSuffix(line, []byte("\n")), []byte("warning: database file for '"))
		if ok {
			name, rest, found := bytes.Cut(repo, []byte("'"))
			if found && len(name) != 0 && !bytes.ContainsAny(name, "' \t") && string(rest) == " does not exist (use '-Sy' to download)" {
				continue
			}
		}
		kept = append(kept, line...)
	}
	return kept
}

// rootRead reads a root-protected, singly linked account file of at most 4 MiB.
func rootRead(path string) ([]byte, error) {
	data, err := custody.ReadRoot(path, 4<<20, false)
	return data, unsafe(err)
}

// unsafe maps custody policy failures onto the provider's ErrUnsafe.
func unsafe(err error) error {
	if errors.Is(err, custody.ErrUnsafe) {
		return fmt.Errorf("%w: %w", ErrUnsafe, err)
	}
	return err
}
func parseRecords(data []byte, fields int) (map[string][]string, error) {
	records := make(map[string][]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != fields || parts[0] == "" || strings.HasPrefix(parts[0], "+") || strings.HasPrefix(parts[0], "-") {
			return nil, ErrUnsafe
		}
		if _, ok := records[parts[0]]; ok {
			return nil, ErrUnsafe
		}
		records[parts[0]] = parts
	}
	return records, nil
}
func readDatabase(nativeDigest func(string, []byte) ([]byte, error)) (*localDB, error) {
	return readDatabaseAt("", nativeDigest)
}

// readDatabaseAt reads the local account files below root ("" is the host).
func readDatabaseAt(root string, nativeDigest func(string, []byte) ([]byte, error)) (db *localDB, err error) {
	if nativeDigest == nil {
		return nil, ErrUnsupported
	}
	db = &localDB{}
	h := sha256.New()
	for _, item := range []struct {
		path   string
		count  int
		target *map[string][]string
	}{{"/etc/passwd", 7, &db.users}, {"/etc/group", 4, &db.groups}, {"/etc/shadow", 9, &db.shadow}, {"/etc/gshadow", 4, &db.gshadow}} {
		data, e := rootRead(root + item.path)
		if item.path == "/etc/gshadow" && errors.Is(e, os.ErrNotExist) {
			// An absent group shadow is part of the revision: creating it
			// later changes every account plan's precondition.
			h.Write([]byte(item.path + "\x00absent"))
			continue
		}
		if e != nil {
			return nil, e
		}
		db.shadowGroups = db.shadowGroups || item.path == "/etc/gshadow"
		*item.target, e = parseRecords(data, item.count)
		if e != nil {
			return nil, e
		}
		digest, e := nativeDigest("accountprovider.database-file.v1:"+item.path, data)
		if e != nil {
			return nil, e
		}
		if len(digest) != 32 {
			return nil, ErrUnsafe
		}
		h.Write([]byte(item.path))
		h.Write([]byte{0})
		h.Write(digest)
	}
	db.revision = h.Sum(nil)
	// Duplicate numeric IDs are ambiguous even when getent happens to return the target first.
	for _, records := range []map[string][]string{db.users, db.groups} {
		seen := make(map[uint32]bool)
		for _, row := range records {
			id, e := number(row[2])
			if e != nil || seen[id] {
				return nil, ErrUnsafe
			}
			seen[id] = true
		}
	}
	for name, row := range db.groups {
		if !db.shadowGroups {
			continue
		}
		shadow := db.gshadow[name]
		if shadow == nil || shadow[2] != "" || !slices.Equal(members(row[3]), members(shadow[3])) {
			return nil, ErrUnsafe
		}
	}
	return db, nil
}
func number(s string) (uint32, error) { n, e := strconv.ParseUint(s, 10, 32); return uint32(n), e }
func members(s string) []string {
	if s == "" {
		return nil
	}
	out := strings.Split(s, ",")
	slices.Sort(out)
	return slices.Compact(out)
}
func (p *Provider) nss(ctx context.Context, table, key string, local []string) ([]byte, error) {
	out, err := p.run(ctx, nil, "/usr/bin/getent", table, key)
	if err != nil {
		var exit *nativeexec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 2 && local == nil && len(out) == 0 {
			return []byte(table + ":" + key + ":absent"), nil
		}
		return nil, fmt.Errorf("%w: NSS lookup", ErrUnsafe)
	}
	if local == nil {
		return nil, fmt.Errorf("%w: directory identity", ErrUnsafe)
	}
	expected := strings.Join(local, ":") + "\n"
	if string(out) != expected {
		return nil, fmt.Errorf("%w: NSS/local mismatch", ErrUnsafe)
	}
	numeric, err := p.run(ctx, nil, "/usr/bin/getent", table, local[2])
	if err != nil || !bytes.Equal(out, numeric) {
		return nil, fmt.Errorf("%w: NSS numeric collision", ErrUnsafe)
	}
	return out, nil
}
func (p *Provider) observeLocal(ctx context.Context, d *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, *resourcev1.ProbeReceipt, *localDB, error) {
	db, err := p.readDB()
	if err != nil {
		return nil, nil, nil, err
	}
	name := d.GetRef().GetCanonicalKey()
	table := "group"
	row := db.groups[name]
	if d.GetLocalUser() != nil {
		table = "passwd"
		row = db.users[name]
	}
	evidence, err := p.nss(ctx, table, name, row)
	if err != nil {
		return nil, nil, nil, err
	}
	o := &resourcev1.ResourceObservation{Ref: proto.CloneOf(d.GetRef()), Metadata: &resourcev1.ObservationMetadata{BootId: p.boot, ExecutorIncarnation: p.config.ExecutorIncarnation, ObservedAt: timestamppb.Now(), Backend: proto.CloneOf(p.backend), NativeRevision: bytes.Clone(db.revision), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}}
	identity := sha256.Sum256([]byte(table + ":" + name + ":absent"))
	if row != nil {
		private := db.gshadow[name]
		if d.GetLocalUser() != nil {
			private = db.shadow[name]
		} else if !db.shadowGroups {
			private = []string{}
		}
		if private == nil || p.config.NativeDigest == nil {
			return nil, nil, nil, ErrUnsafe
		}
		digest, e := p.config.NativeDigest("accountprovider.identity.v1:"+table+":"+name, []byte(strings.Join(row, ":")+"\x00"+strings.Join(private, ":")))
		if e != nil {
			return nil, nil, nil, e
		}
		if len(digest) != 32 {
			return nil, nil, nil, ErrUnsafe
		}
		copy(identity[:], digest)
	}
	snapshot := &agentv1.ResourceOwnershipSnapshot{Observation: o}
	if d.GetLocalGroup() != nil {
		g := &resourcev1.LocalGroupObservation{Name: name, Exists: row != nil, Origin: resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES, LocalFileRevision: bytes.Clone(db.revision), IdentitySha256: identity[:]}
		if row != nil {
			id, e := number(row[2])
			if e != nil {
				return nil, nil, nil, e
			}
			g.Gid = &id
			g.Members = members(row[3])
		}
		o.Observed = &resourcev1.ResourceObservation_LocalGroup{LocalGroup: g}
	} else {
		u := &resourcev1.LocalUserObservation{Name: name, Exists: row != nil, Origin: resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES, LocalFileRevision: bytes.Clone(db.revision), IdentitySha256: identity[:]}
		if row != nil {
			uid, e := number(row[2])
			if e != nil {
				return nil, nil, nil, e
			}
			gid, e := number(row[3])
			if e != nil {
				return nil, nil, nil, e
			}
			u.Uid = &uid
			u.Gid = &gid
			u.Shell = row[6]
			shadow := db.shadow[name]
			if shadow == nil || row[1] != "x" {
				return nil, nil, nil, ErrUnsafe
			}
			locked := strings.HasPrefix(shadow[1], "!") || strings.HasPrefix(shadow[1], "*")
			u.PasswordLocked = &locked
			token := strings.TrimLeft(shadow[1], "!")
			var algorithm resourcev1.PasswordHashAlgorithm
			switch {
			case strings.HasPrefix(token, "$y$"):
				algorithm = resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_YESCRYPT
			case strings.HasPrefix(token, "$6$"):
				algorithm = resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT
			case strings.HasPrefix(token, "$2a$") || strings.HasPrefix(token, "$2b$") || strings.HasPrefix(token, "$2y$"):
				algorithm = resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_BCRYPT
			}
			if algorithm != 0 {
				u.PasswordAlgorithm = &algorithm
			}
			u.Aging, e = parseAging(shadow)
			if e != nil {
				return nil, nil, nil, e
			}
			for group, g := range db.groups {
				if slices.Contains(members(g[3]), name) {
					u.Groups = append(u.Groups, group)
				}
			}
			slices.Sort(u.Groups)
			groupEvidence, e := p.verifyGroups(ctx, db, u)
			if e != nil {
				return nil, nil, nil, e
			}
			evidence = append(evidence, groupEvidence...)
			u.HasProcesses, e = processesForUID(uid)
			if e != nil {
				return nil, nil, nil, e
			}
			u.Home, e = homeMetadata(row[5])
			if e != nil {
				return nil, nil, nil, e
			}
			u.HasExternalData = u.GetHome().GetExists()
			for _, mail := range []string{"/var/mail/" + name, "/var/spool/mail/" + name} {
				if _, e := os.Lstat(mail); e == nil {
					u.HasExternalData = true
				} else if !errors.Is(e, os.ErrNotExist) {
					return nil, nil, nil, e
				}
			}
			snapshot.AccountPrivate = &agentv1.ResourceAccountPrivate{PasswordToken: proto.String(shadow[1])}
		}
		o.Observed = &resourcev1.ResourceObservation_LocalUser{LocalUser: u}
	}
	generation := uuid.NewSHA1(uuid.NameSpaceOID, identity[:]).String()
	anchor := sha256.Sum256([]byte(generation))
	if snapshot.AccountPrivate == nil {
		snapshot.AccountPrivate = &agentv1.ResourceAccountPrivate{}
	}
	snapshot.AccountPrivate.NativeGeneration = generation
	snapshot.AccountPrivate.IdentityAnchorSha256 = bytes.Clone(anchor[:])
	if u := o.GetLocalUser(); u != nil && u.GetExists() {
		u.UidGeneration = proto.String(generation)
	}
	if p.config.NativeDigest == nil {
		return nil, nil, nil, ErrUnsafe
	}
	digest, err := p.config.NativeDigest("accountprovider.nss-evidence.v1", evidence)
	clear(evidence)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(digest) != sha256.Size {
		return nil, nil, nil, ErrUnsafe
	}
	receipt := &resourcev1.ProbeReceipt{ProbeId: uuid.NewString(), ObservedAt: timestamppb.Now(), Passed: true, EvidenceSha256: digest, Reason: "Independent getent name and numeric identity matched protected local records"}
	return snapshot, receipt, db, nil
}
func homeMetadata(path string) (*resourcev1.HomeMetadata, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnsafe
	}
	h := &resourcev1.HomeMetadata{Path: path}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); errors.Is(err, unix.ENOENT) {
		return h, nil
	} else if err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, ErrUnsafe
	}
	h.Exists = true
	h.OwnerUid = st.Uid
	h.OwnerGid = st.Gid
	h.Mode = st.Mode & 07777
	h.Device = uint64(st.Dev)
	h.Inode = st.Ino
	return h, nil
}
func parseAging(row []string) (*resourcev1.PasswordAging, error) {
	a := &resourcev1.PasswordAging{}
	for _, v := range []struct {
		index  int
		target **uint32
	}{{3, &a.MinDays}, {4, &a.MaxDays}, {5, &a.WarnDays}, {6, &a.InactiveDays}} {
		if row[v.index] != "" && row[v.index] != "-1" {
			n, e := number(row[v.index])
			if e != nil || n > 99999 {
				return nil, ErrUnsafe
			}
			*v.target = &n
		}
	}
	if row[7] == "" || row[7] == "-1" {
		a.AccountNeverExpires = proto.Bool(true)
	} else {
		n, e := strconv.ParseInt(row[7], 10, 32)
		if e != nil {
			return nil, ErrUnsafe
		}
		a.AccountExpiresAt = timestamppb.New(time.Unix(n*86400, 0))
	}
	a.AccountLocked = proto.Bool(row[7] == "1")
	return a, nil
}
func exists(o *resourcev1.ResourceObservation) bool {
	return o.GetLocalGroup().GetExists() || o.GetLocalUser().GetExists()
}
func sameNumericIdentity(a, b *resourcev1.ResourceObservation) bool {
	if a.GetLocalGroup() != nil {
		return a.GetLocalGroup().GetName() == b.GetLocalGroup().GetName() && a.GetLocalGroup().GetGid() == b.GetLocalGroup().GetGid()
	}
	return a.GetLocalUser().GetName() == b.GetLocalUser().GetName() && a.GetLocalUser().GetUid() == b.GetLocalUser().GetUid()
}
