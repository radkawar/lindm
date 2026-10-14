// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
)

// accountLocker uses only local passwd/shadow, not NSS/network identities. The
// production root and native executable are fixed. root is a private-root seam
// for real shadow-utils tests, never serialized configuration or plan data.
// Native failures retain pending ownership; no pending operation is replayed.
// Every release compares the complete passwd identity and all shadow attributes.
// Native shadow-utils provide their own writer locks. An administrator modifying
// files without those locks is outside their serialization contract.
type accountLocker struct {
	store *journal.Store
	root  string
}

func newAccountLocker(store *journal.Store, config *agentv1.DeviceActionProviderConfig) (*accountLocker, error) {
	if config.GetAllowAccountLock() && store == nil {
		return nil, ErrUnsupported
	}
	if store == nil {
		return nil, nil
	}
	return &accountLocker{store: store, root: "/"}, nil
}

func wantsAccountLock(spec *agentv1.DeviceActionSpec) bool {
	return spec.GetLockSessions().GetAllHumanAccounts() || len(spec.GetLockSessions().GetUsernames()) != 0
}

func (p *Provider) accountLockEnabled() error {
	if !p.config.GetAllowAccountLock() || p.accounts == nil || p.accounts.store == nil {
		return ErrUnsupported
	}
	return nil
}

func (p *Provider) accountProtected(name string, uid uint32) bool {
	return name == "root" || uid == 0 || slices.Contains(p.config.GetProtectedAccounts(), name)
}

func (p *Provider) observeAccountLock(ctx context.Context, spec *agentv1.DeviceActionSpec, observation *agentv1.DeviceActionObservation) error {
	if !wantsAccountLock(spec) {
		return nil
	}
	if err := p.accountLockEnabled(); err != nil {
		return err
	}
	accounts, err := p.selectedAccounts(ctx, spec)
	if err != nil {
		return err
	}
	observation.MetadataSha256 = accountDigest(observation.GetMetadataSha256(), accounts)
	for _, account := range accounts {
		if accountDisabled(account, p.clock()) {
			observation.DisabledAccounts = append(observation.DisabledAccounts, account.GetUsername())
		}
		if !accountClaimable(account, p.clock()) {
			observation.PreservedAccounts = append(observation.PreservedAccounts, account.GetUsername())
		}
	}
	return nil
}

func accountDigest(prefix []byte, accounts []*agentv1.AccountLockSnapshot) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("lindm-local-account-lock-v1\x00"))
	_, _ = h.Write(prefix)
	for _, account := range accounts {
		// Length-delimited native lines have no newline. Only this digest leaves
		// root custody; neither password hashes nor shadow attributes are public.
		_, _ = io.WriteString(h, account.GetPasswdEntry())
		_, _ = h.Write([]byte{'\n'})
		_, _ = io.WriteString(h, account.GetShadowEntry())
		_, _ = h.Write([]byte{'\n'})
	}
	return h.Sum(nil)
}

func (p *Provider) applyAccountLock(ctx context.Context, plan *agentv1.DeviceActionPlan) error {
	if !wantsAccountLock(plan.GetSpec()) {
		return nil
	}
	if err := p.accountLockEnabled(); err != nil {
		return err
	}
	accounts, err := p.selectedAccounts(ctx, plan.GetSpec())
	if err != nil {
		return err
	}
	_, sessions, err := p.sessions(ctx, plan.GetSpec().GetLockSessions().GetTerminateSessions())
	if err != nil {
		return err
	}
	if !bytes.Equal(accountDigest(sessions, accounts), plan.GetBefore().GetMetadataSha256()) {
		return ErrConflict
	}
	ledger := &agentv1.AccountLockLedger{LockActionId: plan.GetActionId()}
	for _, account := range accounts {
		entry := &agentv1.AccountLockEntry{Prior: account, Expected: proto.CloneOf(account), Phase: agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_PRESERVED}
		if accountClaimable(account, p.clock()) {
			fields := strings.Split(account.GetShadowEntry(), ":")
			if !strings.HasPrefix(fields[1], "!") {
				fields[1] = "!" + fields[1]
			}
			fields[7] = "1"
			entry.Expected.ShadowEntry = strings.Join(fields, ":")
			entry.Phase = agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_DISABLE_PENDING
		}
		ledger.Accounts = append(ledger.Accounts, entry)
	}
	// The FULL-synchronous SQLite commit precedes even the first native call.
	revision, err := p.accounts.store.CreateAccountLock(ctx, ledger)
	if err != nil {
		return err
	}
	for _, entry := range ledger.GetAccounts() {
		if entry.GetPhase() != agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_DISABLE_PENDING {
			continue
		}
		current, err := p.accounts.lookup(ctx, entry.GetPrior().GetUsername())
		if err != nil || !proto.Equal(current, entry.GetPrior()) {
			return ErrOutcomeUnknown
		}
		if err := p.changeAccount(ctx, ledger.GetLockActionId(), entry.GetPrior(), entry.GetExpected(), true); err != nil {
			return ErrOutcomeUnknown
		}
		current, err = p.accounts.lookup(ctx, entry.GetPrior().GetUsername())
		if err != nil || !proto.Equal(current, entry.GetExpected()) {
			return ErrOutcomeUnknown
		}
		entry.Phase = agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_DISABLED
		revision, err = p.accounts.store.UpdateAccountLock(ctx, revision, ledger)
		if err != nil {
			return ErrOutcomeUnknown
		}
	}
	return nil
}

func (p *Provider) observeReleaseLock(ctx context.Context, spec *agentv1.DeviceActionSpec, observation *agentv1.DeviceActionObservation) error {
	ledger, _, err := p.releaseAccountLedger(ctx, spec.GetReleaseLock().GetLockActionId())
	if err != nil {
		return err
	}
	h := sha256.New()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(ledger)
	if err != nil {
		return ErrConflict
	}
	_, _ = h.Write(encoded)
	clear(encoded)
	for _, entry := range ledger.GetAccounts() {
		current, err := p.accounts.lookup(ctx, entry.GetPrior().GetUsername())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		_, _ = h.Write(accountDigest(nil, []*agentv1.AccountLockSnapshot{current}))
		if current != nil && accountDisabled(current, p.clock()) {
			observation.DisabledAccounts = append(observation.DisabledAccounts, entry.GetPrior().GetUsername())
		}
		if entry.GetPhase() == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_PRESERVED || p.accountProtected(entry.GetPrior().GetUsername(), entry.GetPrior().GetUid()) || (entry.GetPhase() != agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASED && !proto.Equal(current, entry.GetExpected())) {
			observation.PreservedAccounts = append(observation.PreservedAccounts, entry.GetPrior().GetUsername())
		}
	}
	observation.MetadataSha256 = h.Sum(nil)
	return nil
}

func (p *Provider) applyReleaseLock(ctx context.Context, plan *agentv1.DeviceActionPlan) error {
	before := new(agentv1.DeviceActionObservation)
	if err := p.observeReleaseLock(ctx, plan.GetSpec(), before); err != nil {
		return err
	}
	if !bytes.Equal(before.GetMetadataSha256(), plan.GetBefore().GetMetadataSha256()) {
		return ErrConflict
	}
	ledger, revision, err := p.releaseAccountLedger(ctx, plan.GetSpec().GetReleaseLock().GetLockActionId())
	if err != nil {
		return err
	}
	for _, entry := range ledger.GetAccounts() {
		if err := p.accounts.cleanTransaction(ledger.GetLockActionId(), entry.GetPrior().GetUsername()); err != nil {
			return ErrOutcomeUnknown
		}
		phase := entry.GetPhase()
		if phase == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASED || phase == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_PRESERVED {
			continue
		}
		current, err := p.accounts.lookup(ctx, entry.GetPrior().GetUsername())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if phase == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASE_PENDING && proto.Equal(current, entry.GetPrior()) {
			entry.Phase = agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASED
		} else if p.accountProtected(entry.GetPrior().GetUsername(), entry.GetPrior().GetUid()) || !proto.Equal(current, entry.GetExpected()) {
			entry.Phase = agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_PRESERVED
		} else {
			// An ambiguous effect is never replayed by the same action. Only a
			// fresh explicit release with a newly consumed executor gate may
			// restore the still-exact expected state.
			if phase == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASE_PENDING && entry.GetReleaseActionId() == plan.GetActionId() {
				return ErrOutcomeUnknown
			}
			entry.Phase = agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASE_PENDING
			entry.ReleaseActionId = plan.GetActionId()
			revision, err = p.accounts.store.UpdateAccountLock(ctx, revision, ledger)
			if err != nil {
				return err
			}
			// Recheck after the durable commit; changed identity/credentials must
			// never be overwritten with the retained pre-lock account state.
			current, err = p.accounts.lookup(ctx, entry.GetPrior().GetUsername())
			if err != nil || !proto.Equal(current, entry.GetExpected()) {
				return ErrOutcomeUnknown
			}
			if err := p.changeAccount(ctx, ledger.GetLockActionId(), entry.GetExpected(), entry.GetPrior(), false); err != nil {
				return ErrOutcomeUnknown
			}
			current, err = p.accounts.lookup(ctx, entry.GetPrior().GetUsername())
			if err != nil || !proto.Equal(current, entry.GetPrior()) {
				return ErrOutcomeUnknown
			}
			entry.Phase = agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASED
		}
		revision, err = p.accounts.store.UpdateAccountLock(ctx, revision, ledger)
		if err != nil {
			return ErrOutcomeUnknown
		}
	}
	return nil
}

func (p *Provider) verifyAccountLock(ctx context.Context, plan *agentv1.DeviceActionPlan, verification *agentv1.DeviceActionVerification) error {
	release := plan.GetSpec().GetReleaseLock() != nil
	if !release && !wantsAccountLock(plan.GetSpec()) {
		return nil
	}
	var ledger *agentv1.AccountLockLedger
	var err error
	if release {
		ledger, _, err = p.releaseAccountLedger(ctx, plan.GetSpec().GetReleaseLock().GetLockActionId())
	} else {
		if err := p.accountLockEnabled(); err != nil {
			return err
		}
		ledger, _, err = p.accounts.store.LoadAccountLock(ctx, plan.GetActionId())
	}
	if err != nil {
		return err
	}
	if verification.After == nil {
		verification.After = new(agentv1.DeviceActionObservation)
	}
	verification.After.DisabledAccounts = nil
	verification.After.PreservedAccounts = nil
	for _, entry := range ledger.GetAccounts() {
		current, err := p.accounts.lookup(ctx, entry.GetPrior().GetUsername())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if current != nil && accountDisabled(current, p.clock()) {
			verification.After.DisabledAccounts = append(verification.After.DisabledAccounts, entry.GetPrior().GetUsername())
		}
		if entry.GetPhase() == agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_PRESERVED {
			verification.After.PreservedAccounts = append(verification.After.PreservedAccounts, entry.GetPrior().GetUsername())
			continue
		}
		if release {
			if entry.GetPhase() != agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASED || !proto.Equal(current, entry.GetPrior()) {
				return ErrNotVerified
			}
		} else if entry.GetPhase() != agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_DISABLED || !proto.Equal(current, entry.GetExpected()) {
			return ErrNotVerified
		}
	}
	if release {
		verification.Verified = true
		verification.Evidence = "owned unchanged local accounts restored; pre-disabled, protected, changed, and ambiguous accounts preserved; graphical screens not unlocked"
	}
	return nil
}

func (p *Provider) releaseAccountLedger(ctx context.Context, actionID string) (*agentv1.AccountLockLedger, int64, error) {
	if p.accounts == nil || p.accounts.store == nil {
		if p.config.GetAllowAccountLock() {
			return nil, 0, ErrUnsupported
		}
		return &agentv1.AccountLockLedger{LockActionId: actionID}, 0, nil
	}
	ledger, revision, err := p.accounts.store.LoadAccountLock(ctx, actionID)
	if errors.Is(err, journal.ErrAccountLockNotFound) {
		original, _, loadErr := p.accounts.store.LoadDeviceAction(ctx, actionID)
		if loadErr != nil || original.GetIntent().GetSpec().GetLockSessions() == nil {
			return nil, 0, ErrConflict
		}
		return &agentv1.AccountLockLedger{LockActionId: actionID}, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if err := p.accountLockEnabled(); err != nil {
		return nil, 0, err
	}
	return ledger, revision, nil
}

func accountDisabled(account *agentv1.AccountLockSnapshot, now time.Time) bool {
	fields := strings.Split(account.GetShadowEntry(), ":")
	if len(fields) != 9 {
		return false
	}
	expiry, err := strconv.ParseInt(fields[7], 10, 64)
	return err == nil && expiry > 0 && expiry <= now.Unix()/86400
}

func accountClaimable(account *agentv1.AccountLockSnapshot, now time.Time) bool {
	fields := strings.Split(account.GetShadowEntry(), ":")
	return len(fields) == 9 && !accountDisabled(account, now)
}

func (p *Provider) selectedAccounts(ctx context.Context, spec *agentv1.DeviceActionSpec) ([]*agentv1.AccountLockSnapshot, error) {
	local, err := p.accounts.readAccounts(ctx)
	if err != nil {
		return nil, err
	}
	names := slices.Clone(spec.GetLockSessions().GetUsernames())
	if spec.GetLockSessions().GetAllHumanAccounts() {
		if len(p.config.GetProtectedAccounts()) == 0 {
			return nil, ErrUnsupported
		}
		minimum, maximum, shells, err := p.accounts.humanPolicy(ctx)
		if err != nil {
			return nil, err
		}
		for name, account := range local {
			fields := strings.Split(account.GetPasswdEntry(), ":")
			shell := fields[6]
			if account.GetUid() >= minimum && account.GetUid() <= maximum && shells[shell] && filepath.Base(shell) != "nologin" && filepath.Base(shell) != "false" && !p.accountProtected(name, account.GetUid()) {
				names = append(names, name)
			}
		}
	}
	if len(names) > 128 {
		return nil, ErrUnsupported
	}
	slices.Sort(names)
	accounts := make([]*agentv1.AccountLockSnapshot, 0, len(names))
	seenUID := make(map[uint32]bool, len(names))
	for _, name := range names {
		account := local[name]
		if account == nil || p.accountProtected(name, account.GetUid()) || seenUID[account.GetUid()] || account.GetShadowEntry() == "" {
			return nil, ErrConflict
		}
		// An alias for a protected UID is protected too, even when explicitly
		// addressed by a different local login name.
		for protectedName, other := range local {
			if other.GetUid() == account.GetUid() && p.accountProtected(protectedName, other.GetUid()) {
				return nil, ErrConflict
			}
		}
		seenUID[account.GetUid()] = true
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (a *accountLocker) lookup(ctx context.Context, name string) (*agentv1.AccountLockSnapshot, error) {
	accounts, err := a.readAccounts(ctx)
	if err != nil {
		return nil, err
	}
	account := accounts[name]
	if account == nil || account.GetShadowEntry() == "" {
		return nil, os.ErrNotExist
	}
	return account, nil
}

func (a *accountLocker) readAccounts(ctx context.Context) (map[string]*agentv1.AccountLockSnapshot, error) {
	passwd, err := a.readLocal(ctx, "passwd")
	if err != nil {
		return nil, err
	}
	defer clear(passwd)
	shadow, err := a.readLocal(ctx, "shadow")
	if err != nil {
		return nil, err
	}
	defer clear(shadow)
	accounts := make(map[string]*agentv1.AccountLockSnapshot)
	err = accountLines(passwd, func(line string) error {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			return ErrUnsupported
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || accounts[fields[0]] != nil {
			return ErrUnsupported
		}
		accounts[fields[0]] = &agentv1.AccountLockSnapshot{Username: fields[0], Uid: uint32(uid), PasswdEntry: line}
		return nil
	})
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	err = accountLines(shadow, func(line string) error {
		fields := strings.Split(line, ":")
		if len(fields) != 9 || seen[fields[0]] {
			return ErrUnsupported
		}
		seen[fields[0]] = true
		if account := accounts[fields[0]]; account != nil {
			account.ShadowEntry = line
		}
		return nil
	})
	return accounts, err
}

func accountLines(data []byte, use func(string) error) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4097), 4097)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		count++
		if count > 65536 || strings.ContainsAny(line, "\r\x00") {
			return ErrUnsupported
		}
		if err := use(line); err != nil {
			return err
		}
	}
	if scanner.Err() != nil {
		return ErrUnsupported
	}
	return nil
}

func (a *accountLocker) readLocal(ctx context.Context, name string) ([]byte, error) {
	data, err := a.readRooted(ctx, "etc", name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnsupported
	}
	return data, err
}

// openRootedDirectory opens dir below the locker root when root owns it and
// neither group nor others may write it. A missing directory is
// os.ErrNotExist; any other custody failure is ErrUnsupported.
func (a *accountLocker) openRootedDirectory(dir string) (int, error) {
	directoryFD, err := unix.Open(filepath.Join(a.root, dir), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, os.ErrNotExist
	} else if err != nil {
		return -1, ErrUnsupported
	}
	var directoryStat unix.Stat_t
	if unix.Fstat(directoryFD, &directoryStat) != nil || directoryStat.Uid != 0 || directoryStat.Mode&0022 != 0 {
		_ = unix.Close(directoryFD)
		return -1, ErrUnsupported
	}
	return directoryFD, nil
}

// readRooted reads the root-owned regular file dir/name below the locker root.
// A missing directory or file is os.ErrNotExist.
func (a *accountLocker) readRooted(ctx context.Context, dir, name string) (_ []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directoryFD, err := a.openRootedDirectory(dir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, unix.Close(directoryFD)) }()
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, os.ErrNotExist
	} else if err != nil {
		return nil, ErrUnsupported
	}
	file := os.NewFile(uintptr(fd), "local-account-state")
	defer func() { err = errors.Join(err, file.Close()) }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0 || st.Size > 4<<20 || (name == "shadow" && (st.Nlink != 1 || st.Mode&0007 != 0)) {
		return nil, ErrUnsupported
	}
	data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		clear(data)
		return nil, ErrUnsupported
	}
	return data, nil
}

// loginDefinitions returns shadow's login.defs sources in precedence order:
// /etc/login.defs, or on libeconf vendor-directory builds (Tumbleweed ships no
// /etc/login.defs) /usr/etc/login.defs; then the *.defs drop-ins of
// /usr/etc/login.defs.d and /etc/login.defs.d by name, an /etc drop-in
// replacing the same-named vendor one. A later source's value wins.
func (a *accountLocker) loginDefinitions(ctx context.Context) ([][]byte, error) {
	base, err := a.readRooted(ctx, "etc", "login.defs")
	if errors.Is(err, os.ErrNotExist) {
		base, err = a.readRooted(ctx, "usr/etc", "login.defs")
	}
	if err != nil {
		return nil, ErrUnsupported
	}
	dropins := make(map[string]string)
	for _, dir := range []string{"usr/etc/login.defs.d", "etc/login.defs.d"} {
		directoryFD, err := a.openRootedDirectory(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		directory := os.NewFile(uintptr(directoryFD), "login-defs-dropins")
		entries, err := directory.ReadDir(-1)
		err = errors.Join(err, directory.Close())
		if err != nil {
			return nil, ErrUnsupported
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".defs") {
				dropins[entry.Name()] = dir
			}
		}
	}
	sources := [][]byte{base}
	for _, name := range slices.Sorted(maps.Keys(dropins)) {
		data, err := a.readRooted(ctx, dropins[name], name)
		if err != nil {
			return nil, ErrUnsupported
		}
		sources = append(sources, data)
	}
	return sources, nil
}

func (a *accountLocker) humanPolicy(ctx context.Context) (uint32, uint32, map[string]bool, error) {
	sources, err := a.loginDefinitions(ctx)
	if err != nil {
		return 0, 0, nil, err
	}
	var minimum, maximum uint32
	for _, definitions := range sources {
		var sourceMinimum, sourceMaximum uint32
		err = accountLines(definitions, func(line string) error {
			fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(fields) == 0 || (fields[0] != "UID_MIN" && fields[0] != "UID_MAX") {
				return nil
			}
			if len(fields) != 2 {
				return ErrUnsupported
			}
			value, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil || value == 0 {
				return ErrUnsupported
			}
			if fields[0] == "UID_MIN" {
				if sourceMinimum != 0 {
					return ErrUnsupported
				}
				sourceMinimum = uint32(value)
			} else {
				if sourceMaximum != 0 {
					return ErrUnsupported
				}
				sourceMaximum = uint32(value)
			}
			return nil
		})
		if err != nil {
			return 0, 0, nil, ErrUnsupported
		}
		minimum, maximum = cmp.Or(sourceMinimum, minimum), cmp.Or(sourceMaximum, maximum)
	}
	if minimum == 0 || maximum < minimum {
		return 0, 0, nil, ErrUnsupported
	}
	shellData, err := a.readLocal(ctx, "shells")
	if err != nil {
		return 0, 0, nil, err
	}
	shells := make(map[string]bool)
	err = accountLines(shellData, func(line string) error {
		shell := strings.TrimSpace(line)
		if !filepath.IsAbs(shell) || filepath.Clean(shell) != shell {
			return ErrUnsupported
		}
		shells[shell] = true
		return nil
	})
	return minimum, maximum, shells, err
}
