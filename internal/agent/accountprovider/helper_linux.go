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

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/statefs"
	"lindm/internal/resource"
)

type command struct {
	tool  string
	args  []string
	stdin []byte
}

// ExecuteNative is only for the fixed root account transient helper. The parent
// provisions a private account-root with the exact host /etc bind and no other
// children. Shadow tools use that fixed prefix (chage may use a preselected root)
// so implicit UID/GID chown cannot reach host homes or mail. New home creation
// remains an exact approved host mkdir. No caller supplies argv or scripts.
type NativeConfig struct {
	Native              *agentv1.NativeAccountProviderConfig
	Platform            *resourcev1.PlatformProduct
	ExecutorIncarnation string
	AccountRoot         string
	NativeDigest        func(string, []byte) ([]byte, error)
}

func ExecuteNative(ctx context.Context, config NativeConfig, request *agentv1.NativeResourceTransactionRequest, beforeEffect func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := CheckNative(ctx, config); err != nil {
		return err
	}
	if err := validateAccountRoot(config.AccountRoot, ChrootAccountRoot(config.Platform)); err != nil {
		return err
	}
	return executeNative(ctx, config, request, beforeEffect, runNative, func() (*localDB, error) { return readDatabase(config.NativeDigest) })
}
func executeNative(ctx context.Context, config NativeConfig, r *agentv1.NativeResourceTransactionRequest, beforeEffect func(context.Context) error, run nativeRun, readDB func() (*localDB, error)) error {
	if r == nil || r.Plan == nil || r.Before == nil || r.Target == nil || beforeEffect == nil {
		return ErrUnsafe
	}
	if err := resource.ValidatePlan(r.Plan); err != nil {
		return err
	}
	if !proto.Equal(r.Plan.GetBefore(), r.Before.GetObservation()) {
		return ErrConflict
	}
	if err := checkHooks(); err != nil {
		return err
	}
	db, err := readDB()
	if err != nil {
		return err
	}
	if !bytes.Equal(db.revision, r.Before.GetObservation().GetMetadata().GetNativeRevision()) {
		return ErrConflict
	}
	// Independent NSS checks include every member and referenced numeric identity.
	p := &Provider{run: run, config: Config{Native: config.Native, NativeDigest: config.NativeDigest, Ownership: r.GetOwnership().GetOwner(), ActionID: r.GetActionId(), Secrets: helperPasswordHash(r)}}
	if err := p.validateDesired(resource.PlanDesired(r.Plan)); err != nil {
		return err
	}
	if p.isAdministrator(db, r.Plan.GetRef().GetCanonicalKey()) {
		return ErrUnsafe
	}
	if err := validateNativeTarget(ctx, p, r, db); err != nil {
		return err
	}
	commands, err := nativeCommands(r, db)
	if err != nil {
		return err
	}
	table := "group"
	name := r.Plan.GetRef().GetCanonicalKey()
	row := db.groups[name]
	if r.Plan.GetLocalUser() != nil {
		table = "passwd"
		row = db.users[name]
	}
	if _, err = p.nss(ctx, table, name, row); err != nil {
		return err
	}
	for _, edge := range edgeDifference(r.Before.GetObservation(), r.Target.GetObservation()) {
		if u := db.users[edge.GetUser()]; u != nil {
			if _, err = p.nss(ctx, "passwd", edge.GetUser(), u); err != nil {
				return err
			}
		}
		if g := db.groups[edge.GetGroup()]; g != nil {
			if _, err = p.nss(ctx, "group", edge.GetGroup(), g); err != nil {
				return err
			}
		}
	}
	if exists(r.Target.GetObservation()) {
		id := r.Target.GetObservation().GetLocalGroup().GetGid()
		if r.Plan.GetLocalUser() != nil {
			id = r.Target.GetObservation().GetLocalUser().GetUid()
		}
		key := strconv.FormatUint(uint64(id), 10)
		var same []string
		if row != nil && row[2] == key {
			same = row
		}
		if _, err = p.nss(ctx, table, key, same); err != nil {
			return err
		}
	}
	if u := r.Plan.GetLocalUser(); u != nil {
		before, target := r.Before.GetObservation().GetLocalUser(), r.Target.GetObservation().GetLocalUser()
		if target.GetExists() {
			found := false
			for group, g := range db.groups {
				if g[2] == decimal(target.GetGid()) {
					found = true
					if _, err = p.nss(ctx, "group", group, g); err != nil {
						return err
					}
				}
			}
			if !found {
				return ErrUnsafe
			}
		}
		if before.GetExists() && (!target.GetExists() || before.GetUid() != target.GetUid()) {
			busy, e := processesForUID(before.GetUid())
			if e != nil {
				return e
			}
			if busy {
				return ErrConflict
			}
		}
		if before.GetExists() && target.GetExists() && (before.GetUid() != target.GetUid() || before.GetGid() != target.GetGid()) {
			for _, home := range []*resourcev1.HomeMetadata{before.GetHome(), target.GetHome()} {
				path := home.GetPath()
				if path == "/" || path == "/etc" || strings.HasPrefix(path, "/etc/") {
					return fmt.Errorf("%w: account home overlaps the exposed native database", ErrUnsafe)
				}
			}
		}
	}
	options, err := nativeToolOptions(ctx, run, commands, ChrootAccountRoot(config.Platform))
	if err != nil {
		return err
	}
	prefixCommands(commands, config.AccountRoot, options)
	if err = checkHooks(); err != nil {
		return err
	}
	if err = runCommands(ctx, commands, db.revision, beforeEffect, run, readDB); err != nil {
		return err
	}
	if u := r.Plan.GetLocalUser(); u != nil && u.GetCreateHome() {
		if err = createHome(r.Target.GetObservation().GetLocalUser()); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
	}
	return nil
}

// runCommands consumes authority once after the last full DB precondition. A
// subprocess failure is UNKNOWN and never retries this or a later command.
func runCommands(ctx context.Context, commands []command, revision []byte, beforeEffect func(context.Context) error, run nativeRun, readDB func() (*localDB, error)) error {
	fresh, err := readDB()
	if err != nil {
		return err
	}
	if !bytes.Equal(fresh.revision, revision) {
		return ErrConflict
	}
	if err = beforeEffect(ctx); err != nil {
		return err
	}
	for i, cmd := range commands {
		if i != 0 {
			fresh, err = readDB()
			if err != nil {
				return errors.Join(ErrOutcomeUnknown, err)
			}
			if !bytes.Equal(fresh.revision, revision) {
				return ErrOutcomeUnknown
			}
		}
		_, err = run(ctx, cmd.stdin, cmd.tool, cmd.args...)
		clear(cmd.stdin)
		if err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
		fresh, err = readDB()
		if err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
		revision = fresh.revision
	}
	return nil
}
func checkHooks() error {
	data, err := protectedRead("/etc/login.defs")
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && (fields[0] == "USERDEL_CMD" || fields[0] == "USERADD_CMD") {
			return fmt.Errorf("%w: native account hook configured", ErrUnsupported)
		}
	}
	for _, path := range []string{"/etc/shadow-maint/useradd-pre.d", "/etc/shadow-maint/useradd-post.d", "/etc/shadow-maint/userdel-pre.d", "/etc/shadow-maint/userdel-post.d"} {
		entries, e := os.ReadDir(path)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if len(entries) != 0 {
			return fmt.Errorf("%w: native account hook directory", ErrUnsupported)
		}
	}
	return nil
}
func nativeCommands(r *agentv1.NativeResourceTransactionRequest, db *localDB) ([]command, error) {
	before, target := r.Before.GetObservation(), r.Target.GetObservation()
	name := r.Plan.GetRef().GetCanonicalKey()
	var out []command
	appendCommand := func(tool string, args ...string) {
		path := "/usr/sbin/" + tool
		if tool == "chage" {
			path = "/usr/bin/chage"
		}
		out = append(out, command{tool: path, args: args})
	}
	// The encrypted token reaches chpasswd only on stdin, never argv or env.
	setPassword := func(user, token string) {
		stdin := make([]byte, 0, len(user)+len(token)+2)
		stdin = append(append(append(append(stdin, user...), ':'), token...), '\n')
		out = append(out, command{tool: "/usr/sbin/chpasswd", args: []string{"--encrypted"}, stdin: stdin})
	}
	if g := target.GetLocalGroup(); g != nil {
		old := before.GetLocalGroup()
		switch {
		case !old.GetExists() && g.GetExists():
			appendCommand("groupadd", "--gid", decimal(g.GetGid()), "--", name)
		case old.GetExists() && !g.GetExists():
			for _, u := range db.users {
				if u[3] == decimal(old.GetGid()) {
					return nil, ErrUnsafe
				}
			}
			appendCommand("groupdel", "--", name)
			return out, nil
		case old.GetExists() && g.GetExists() && old.GetGid() != g.GetGid():
			appendCommand("groupmod", "--gid", decimal(g.GetGid()), "--", name)
		}
	} else {
		old, u := before.GetLocalUser(), target.GetLocalUser()
		from, to := r.Before.GetAccountPrivate().GetPasswordToken(), r.Target.GetAccountPrivate().GetPasswordToken()
		switch {
		case !old.GetExists() && u.GetExists():
			appendCommand("useradd", "--no-create-home", "--no-user-group", "--no-log-init", "--uid", decimal(u.GetUid()), "--gid", decimal(u.GetGid()), "--home-dir", u.GetHome().GetPath(), "--shell", u.GetShell(), "--password", "!", "--inactive", "-1", "--expiredate", "", "--", name)
			if to != "!" {
				if !encryptedToken(to) {
					return nil, fmt.Errorf("%w: created password token", ErrUnsafe)
				}
				setPassword(name, to)
			}
		case old.GetExists() && !u.GetExists():
			if db.groups[name] != nil {
				return nil, fmt.Errorf("%w: userdel could remove an unrelated private group", ErrUnsafe)
			}
			appendCommand("userdel", "--", name)
			return out, nil
		case old.GetExists() && u.GetExists():
			var args []string
			if old.GetUid() != u.GetUid() {
				args = append(args, "--uid", decimal(u.GetUid()))
			}
			if old.GetGid() != u.GetGid() {
				args = append(args, "--gid", decimal(u.GetGid()))
			}
			if old.GetHome().GetPath() != u.GetHome().GetPath() {
				args = append(args, "--home", u.GetHome().GetPath())
			}
			if old.GetShell() != u.GetShell() {
				args = append(args, "--shell", u.GetShell())
			}
			password := ""
			if from != to {
				switch {
				case to == "!"+from:
					args = append(args, "--lock")
				case from == "!"+to && to != "" && !strings.HasPrefix(to, "!") && !strings.HasPrefix(to, "*"):
					args = append(args, "--unlock")
				case lockMarker(to):
					// A bare lock marker is not credential material; newer
					// chpasswd rejects "!!" as an invalid hash.
					args = append(args, "--password", to)
				case encryptedToken(to):
					password = to
				default:
					return nil, fmt.Errorf("%w: private password restoration mismatch", ErrUnsafe)
				}
			}
			if len(args) > 0 {
				args = append(args, "--", name)
				appendCommand("usermod", args...)
			}
			if password != "" {
				setPassword(name, password)
			}
		}
		if u.GetExists() {
			args := agingArgs(old.GetAging(), u.GetAging())
			if len(args) > 0 {
				args = append(args, "--", name)
				appendCommand("chage", args...)
			}
		}
	}
	// Build full supplementary sets from protected local rows, changing only the
	// explicitly planned edges. usermod -G never receives an NSS/directory group.
	byUser := make(map[string][]string)
	for _, edge := range edgeDifference(before, target) {
		if _, ok := byUser[edge.GetUser()]; !ok {
			var current []string
			for group, row := range db.groups {
				if slices.Contains(members(row[3]), edge.GetUser()) {
					current = append(current, group)
				}
			}
			byUser[edge.GetUser()] = current
		}
		groups := byUser[edge.GetUser()]
		if edge.GetPresent() {
			if !slices.Contains(groups, edge.GetGroup()) {
				groups = append(groups, edge.GetGroup())
			}
		} else {
			groups = slices.DeleteFunc(groups, func(g string) bool { return g == edge.GetGroup() })
		}
		slices.Sort(groups)
		byUser[edge.GetUser()] = groups
	}
	users := make([]string, 0, len(byUser))
	for user := range byUser {
		users = append(users, user)
	}
	slices.Sort(users)
	for _, user := range users {
		appendCommand("usermod", "--groups", strings.Join(byUser[user], ","), "--", user)
	}
	for _, cmd := range out {
		if len(cmd.args) > 64 || len(cmd.stdin) > 1024 {
			return nil, ErrUnsafe
		}
		size := 0
		for _, arg := range cmd.args {
			size += len(arg)
			if strings.ContainsAny(arg, "\x00\r\n") {
				return nil, ErrUnsafe
			}
		}
		if size > 65536 {
			return nil, ErrUnsafe
		}
	}
	return out, nil
}

// lockMarker is a shadow password field made only of lock characters, such as
// "!" or "!!": it contains no credential and may be restored through usermod.
func lockMarker(token string) bool {
	return token != "" && strings.Trim(token, "!*") == ""
}

// encryptedToken accepts a nonempty single shadow field for chpasswd
// --encrypted. Empty (passwordless) tokens are never written.
func encryptedToken(token string) bool {
	return token != "" && len(token) <= 520 && !strings.ContainsAny(token, ":\x00\r\n") && !lockMarker(token)
}

// helperPasswordHash serves the root helper's target recomputation. Its only
// source is the executor-built target, derived from the authenticated sealed
// delivery; target() revalidates the hash shape and declared algorithm.
func helperPasswordHash(r *agentv1.NativeResourceTransactionRequest) func(context.Context, *resourcev1.SecretRef) (*agentv1.SecretMaterial, error) {
	return func(_ context.Context, ref *resourcev1.SecretRef) (*agentv1.SecretMaterial, error) {
		hashed := resource.PlanDesired(r.GetPlan()).GetLocalUser().GetPassword().GetHashed()
		if hashed == nil || !proto.Equal(hashed.GetHash(), ref) || r.GetPlan().GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE {
			return nil, ErrUnsafe
		}
		return &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_PasswordHash{PasswordHash: []byte(r.GetTarget().GetAccountPrivate().GetPasswordToken())}}, nil
	}
}
func decimal(v uint32) string { return strconv.FormatUint(uint64(v), 10) }
func agingArgs(old, next *resourcev1.PasswordAging) []string {
	var out []string
	if old == nil {
		old = &resourcev1.PasswordAging{}
	}
	if next == nil {
		next = &resourcev1.PasswordAging{}
	}
	for _, field := range []struct {
		flag string
		a, b *uint32
	}{{"--mindays", old.MinDays, next.MinDays}, {"--maxdays", old.MaxDays, next.MaxDays}, {"--warndays", old.WarnDays, next.WarnDays}, {"--inactive", old.InactiveDays, next.InactiveDays}} {
		if field.a == nil && field.b == nil || field.a != nil && field.b != nil && *field.a == *field.b {
			continue
		}
		value := "-1"
		if field.b != nil {
			value = decimal(*field.b)
		}
		out = append(out, field.flag, value)
	}
	if !proto.Equal(old.GetAccountExpiresAt(), next.GetAccountExpiresAt()) || old.GetAccountNeverExpires() != next.GetAccountNeverExpires() {
		value := "-1"
		if next.GetAccountExpiresAt() != nil {
			value = strconv.FormatInt(next.GetAccountExpiresAt().AsTime().Unix()/86400, 10)
		}
		out = append(out, "--expiredate", value)
	}
	return out
}
func createHome(u *resourcev1.LocalUserObservation) (err error) {
	path := u.GetHome().GetPath()
	if path == "" || filepath.Clean(path) != path {
		return ErrUnsafe
	}
	if err = protectedAncestry(filepath.Dir(path)); err != nil {
		return err
	}
	parent, err := statefs.OpenTemporaryParent(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(parent)) }()
	name := filepath.Base(path)
	if err = unix.Mkdirat(parent, name, 0700); err != nil {
		return err
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	if err = unix.Fchown(fd, int(u.GetUid()), int(u.GetGid())); err != nil {
		return err
	}
	if err = unix.Fchmod(fd, u.GetHome().GetMode()); err != nil {
		return err
	}
	return unix.Fsync(parent)
}
func inverseDigest(snapshot, baseline *agentv1.ResourceOwnershipSnapshot, nativeDigest func(string, []byte) ([]byte, error)) ([]byte, error) {
	if nativeDigest == nil || snapshot == nil || baseline == nil {
		return nil, ErrUnsafe
	}
	// Ciphertext is revision-bound and randomized; only a keyed process-local
	// projection of the decrypted baseline is stable across the durable Begin.
	private := proto.CloneOf(baseline)
	if private.AccountPrivate != nil {
		private.AccountPrivate.EncryptedPasswordToken = nil
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(private)
	if err != nil {
		return nil, err
	}
	baselineDigest, err := nativeDigest("accountprovider.inverse-baseline.v1", encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	if len(baselineDigest) != sha256.Size {
		return nil, ErrUnsafe
	}
	observation := proto.CloneOf(snapshot.GetObservation())
	observation.Metadata = nil
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(observation)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte("lindm.account-inverse.v1\x00"))
	h.Write(baselineDigest[:])
	h.Write([]byte(snapshot.GetAccountPrivate().GetNativeGeneration()))
	h.Write(snapshot.GetAccountPrivate().GetIdentityAnchorSha256())
	h.Write(data)
	return h.Sum(nil), nil
}
