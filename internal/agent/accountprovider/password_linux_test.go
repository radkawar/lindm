//go:build linux

package accountprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Shape-valid crypt(3) fields. Shadow stores them verbatim; no login is tested.
var (
	sha512Hash   = "$6$lindmsalt$" + strings.Repeat("A", 86)
	driftHash    = "$6$othersalt$" + strings.Repeat("B", 86)
	baselineHash = "$6$baseline$" + strings.Repeat("C", 86)
	yescryptHash = "$y$j9T$lindmsalt$" + strings.Repeat("D", 43)
)

func staticHash(t *testing.T, want *resourcev1.SecretRef, hash string) func(context.Context, *resourcev1.SecretRef) (*agentv1.SecretMaterial, error) {
	t.Helper()
	return func(_ context.Context, ref *resourcev1.SecretRef) (*agentv1.SecretMaterial, error) {
		if !proto.Equal(ref, want) {
			return nil, errors.New("undelivered secret reference")
		}
		return &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_PasswordHash{PasswordHash: []byte(hash)}}, nil
	}
}

func hashedDesired(algorithm resourcev1.PasswordHashAlgorithm) (*resourcev1.ResourceDesiredState, *resourcev1.SecretRef) {
	d := userDesired()
	ref := &resourcev1.SecretRef{SecretId: uuid.NewString(), Version: 1, Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, SubjectBindingId: uuid.NewString()}
	d.GetLocalUser().Password = &resourcev1.PasswordState{State: &resourcev1.PasswordState_Hashed{Hashed: &resourcev1.HashedPasswordPolicy{Hash: ref, Algorithm: algorithm}}}
	return d, ref
}

func passwordRequest(d *resourcev1.ResourceDesiredState, op resourcev1.ResourceOperation, before, target *agentv1.ResourceOwnershipSnapshot) *agentv1.NativeResourceTransactionRequest {
	return &agentv1.NativeResourceTransactionRequest{Before: before, Target: target, Plan: &resourcev1.ResourcePlan{Ref: proto.CloneOf(d.GetRef()), Operation: op, Plan: &resourcev1.ResourcePlan_LocalUser{LocalUser: &resourcev1.LocalUserPlan{Desired: d.GetLocalUser()}}}}
}

// requireStdinOnly proves the hash crosses to chpasswd only on stdin.
func requireStdinOnly(t *testing.T, commands []command, user, token string) {
	t.Helper()
	found := false
	for _, cmd := range commands {
		for _, arg := range cmd.args {
			if strings.Contains(arg, "$6$") || strings.Contains(arg, "$y$") {
				t.Fatal("password hash escaped to argv")
			}
		}
		if cmd.tool == "/usr/sbin/chpasswd" {
			if !slices.Equal(cmd.args, []string{"--encrypted"}) || string(cmd.stdin) != user+":"+token+"\n" {
				t.Fatalf("chpasswd did not receive exactly one encrypted stdin record: %q", cmd.args)
			}
			found = true
		} else if cmd.stdin != nil {
			t.Fatal("non-password tool received stdin")
		}
	}
	if !found {
		t.Fatal("hashed password was not applied through chpasswd")
	}
}

func TestHashedPasswordDriftConvergeAndRelease(t *testing.T) {
	p := testProvider()
	d, ref := hashedDesired(resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT)
	p.config.Secrets = staticHash(t, ref, sha512Hash)
	baseline := fixtureSnapshot(false)
	baseline.AccountPrivate.PasswordToken = proto.String("!" + baselineHash)
	baseline.Observation.GetLocalUser().PasswordLocked = proto.Bool(true)

	target, _, err := p.target(context.Background(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, baseline, fixtureDB(), nil)
	if err != nil {
		t.Fatal(err)
	}
	user := target.GetObservation().GetLocalUser()
	if target.GetAccountPrivate().GetPasswordToken() != sha512Hash || user.GetPasswordLocked() || user.GetPasswordAlgorithm() != resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT {
		t.Fatal("drifted shadow field did not target the delivered hash")
	}
	if !slices.Equal(changedFields(baseline, target), []resourcev1.UserField{resourcev1.UserField_USER_FIELD_PASSWORD}) {
		t.Fatalf("public plan fields = %v", changedFields(baseline, target))
	}
	public, err := proto.Marshal(&resourcev1.LocalUserPlan{Desired: d.GetLocalUser(), Fields: changedFields(baseline, target)})
	if err != nil || bytes.Contains(public, []byte(sha512Hash)) {
		t.Fatal("public plan carries the password hash")
	}
	commands, err := nativeCommands(passwordRequest(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, baseline, target), fixtureDB())
	if err != nil {
		t.Fatal(err)
	}
	requireStdinOnly(t, commands, "alice", sha512Hash)

	converged, _, err := p.target(context.Background(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, target, fixtureDB(), nil)
	if err != nil || !sameState(target, converged) || len(dimensions(target, converged)) != 0 {
		t.Fatalf("converged hash planned another change: %v", err)
	}

	dims := dimensions(baseline, target)
	if !slices.Equal(dims, []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PASSWORD_LOCK}) {
		t.Fatalf("owned dimensions = %v", dims)
	}
	restored, _, err := releaseTarget(target, appliedLedger(baseline, target, dims...))
	if err != nil {
		t.Fatal(err)
	}
	if restored.GetAccountPrivate().GetPasswordToken() != "!"+baselineHash {
		t.Fatal("release did not restore the exact baseline shadow field")
	}
	commands, err = nativeCommands(passwordRequest(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, target, restored), fixtureDB())
	if err != nil {
		t.Fatal(err)
	}
	requireStdinOnly(t, commands, "alice", "!"+baselineHash)

	// A pure lock marker baseline carries no credential and is restored
	// through usermod; an empty (passwordless) field is never written.
	marker := proto.CloneOf(restored)
	marker.AccountPrivate.PasswordToken = proto.String("!!")
	commands, err = nativeCommands(passwordRequest(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, target, marker), fixtureDB())
	if err != nil || len(commands) != 1 || !slices.Equal(commands[0].args, []string{"--password", "!!", "--", "alice"}) {
		t.Fatalf("lock marker restore = %v %v", commands, err)
	}
	marker.AccountPrivate.PasswordToken = proto.String("")
	if _, err := nativeCommands(passwordRequest(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, target, marker), fixtureDB()); !errors.Is(err, ErrUnsafe) {
		t.Fatal("passwordless shadow field accepted")
	}
}

// The root helper recomputes the target from the executor-built request, so
// an injected token that is not a hash of the declared algorithm is refused.
func TestHelperRevalidatesTargetHash(t *testing.T) {
	d, _ := hashedDesired(resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_YESCRYPT)
	for _, token := range []string{yescryptHash, sha512Hash, "!" + yescryptHash} {
		target := fixtureSnapshot(false)
		target.AccountPrivate.PasswordToken = proto.String(token)
		r := passwordRequest(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, fixtureSnapshot(false), target)
		p := testProvider()
		p.config.Secrets = helperPasswordHash(r)
		got, _, err := p.target(context.Background(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, fixtureSnapshot(false), fixtureDB(), nil)
		if token == yescryptHash {
			if err != nil || got.GetAccountPrivate().GetPasswordToken() != token {
				t.Fatalf("valid helper target refused: %v", err)
			}
		} else if !errors.Is(err, ErrUnsafe) {
			t.Fatalf("helper accepted target token %q: %v", token[:4], err)
		}
	}
}

// TestNativeHashedPasswordLifecycle drives the real shadow tools against a
// private account root: creation with a delivered hash, drift remediation,
// convergence and release to the prior baseline field.
func TestNativeHashedPasswordLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("real private-root shadow tests require root")
	}
	for _, tool := range []string{"/usr/sbin/useradd", "/usr/sbin/chpasswd", "/usr/bin/chage"} {
		if _, err := os.Stat(tool); errors.Is(err, os.ErrNotExist) {
			t.Skip("native shadow-utils is unavailable")
		} else if err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"passwd":     "root:x:0:0:root:/root:/bin/sh\nexternal:x:2002:2003::/home/external:/bin/sh\n",
		"group":      "root:x:0:\nengineers:x:2000:external\nexternal:x:2003:\n",
		"shadow":     "root:!:20000:0:99999:7:::\nexternal:!:20000:0:99999:7:::\n",
		"gshadow":    "root:*::\nengineers:!::external\nexternal:!::\n",
		"login.defs": "UID_MIN 1000\nUID_MAX 60000\nGID_MIN 1000\nGID_MAX 60000\n",
	} {
		mode := os.FileMode(0644)
		if strings.Contains(name, "shadow") {
			mode = 0600
		}
		if err := os.WriteFile(filepath.Join(root, "etc", name), []byte(value), mode); err != nil {
			t.Fatal(err)
		}
	}
	field := func() string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, "etc", "shadow"))
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			if fields := strings.Split(line, ":"); fields[0] == "alice" && len(fields) == 9 {
				return fields[1]
			}
		}
		return ""
	}
	execute := func(commands []command) {
		t.Helper()
		var recorded []string
		run := func(ctx context.Context, stdin []byte, path string, args ...string) ([]byte, error) {
			recorded = append(recorded, strings.Join(args, " "))
			return runNative(ctx, stdin, path, args...)
		}
		options, err := nativeToolOptions(t.Context(), run, commands)
		if err != nil {
			t.Fatal(err)
		}
		prefixCommands(commands, root, options)
		for _, cmd := range commands {
			if _, err := run(t.Context(), cmd.stdin, cmd.tool, cmd.args...); err != nil {
				t.Fatalf("%s: %v", filepath.Base(cmd.tool), err)
			}
		}
		for _, argv := range recorded {
			if strings.Contains(argv, "$6$") {
				t.Fatal("password hash escaped to native argv")
			}
		}
	}
	p := testProvider()
	d, ref := hashedDesired(resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT)
	user := d.GetLocalUser()
	user.Uid = proto.Uint32(2010)
	user.PrimaryGroup = proto.String("engineers")
	user.HomeDirectory = proto.String("/nonexistent/lindm-test-alice")
	user.Shell = &resourcev1.LoginShell{InstalledShell: "/bin/sh"}
	db := fixtureDB()
	delete(db.users, "alice")
	absent := fixtureSnapshot(false)
	absent.Observation.Observed = &resourcev1.ResourceObservation_LocalUser{LocalUser: &resourcev1.LocalUserObservation{Name: "alice", Origin: resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES, LocalFileRevision: bytes.Repeat([]byte{1}, 32), IdentitySha256: bytes.Repeat([]byte{3}, 32)}}
	absent.AccountPrivate.PasswordToken = nil
	absent.AccountPrivate.DesiredHome = &resourcev1.HomeMetadata{Path: user.GetHomeDirectory()}

	p.config.Secrets = staticHash(t, ref, sha512Hash)
	created, _, err := p.target(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, absent, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	commands, err := nativeCommands(passwordRequest(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, absent, created), db)
	if err != nil {
		t.Fatal(err)
	}
	requireStdinOnly(t, commands, "alice", sha512Hash)
	execute(commands)
	if field() != sha512Hash {
		t.Fatal("created account does not carry the delivered hash")
	}

	// Drift: the observed field differs; remediation rewrites exactly it.
	drifted := proto.CloneOf(created)
	drifted.AccountPrivate.PasswordToken = proto.String(driftHash)
	commands, err = nativeCommands(passwordRequest(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, created, drifted), db)
	if err != nil {
		t.Fatal(err)
	}
	execute(commands)
	if field() != driftHash {
		t.Fatal("fixture drift was not applied")
	}
	remediated, _, err := p.target(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, drifted, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	commands, err = nativeCommands(passwordRequest(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, drifted, remediated), db)
	if err != nil {
		t.Fatal(err)
	}
	requireStdinOnly(t, commands, "alice", sha512Hash)
	execute(commands)
	if field() != sha512Hash {
		t.Fatal("drift was not remediated to the delivered hash")
	}
	converged, _, err := p.target(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, remediated, db, nil)
	if err != nil || !sameState(remediated, converged) {
		t.Fatalf("converged account planned a change: %v", err)
	}

	// Release restores the exact baseline field captured before ownership.
	baseline := proto.CloneOf(remediated)
	baseline.AccountPrivate.PasswordToken = proto.String(baselineHash)
	restored, _, err := releaseTarget(remediated, appliedLedger(baseline, remediated, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PASSWORD_LOCK))
	if err != nil {
		t.Fatal(err)
	}
	commands, err = nativeCommands(passwordRequest(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, remediated, restored), db)
	if err != nil {
		t.Fatal(err)
	}
	execute(commands)
	if field() != baselineHash {
		t.Fatal("release did not restore the baseline hash")
	}
}
