//go:build linux

package accountprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/custody"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

var validator = sync.OnceValues(func() (protovalidate.Validator, error) { return protovalidate.New() })

func rootOwned(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return ErrUnsafe
	}
	return nil
}
func validateMessage(message proto.Message) error {
	if message == nil || !message.ProtoReflect().IsValid() {
		return ErrUnsafe
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return err
	}
	v, err := validator()
	if err != nil {
		return err
	}
	return v.Validate(message)
}
func validateNativeConfig(c *agentv1.NativeAccountProviderConfig) error {
	if err := validateMessage(c); err != nil {
		return err
	}
	for _, root := range c.GetApprovedHomeRoots() {
		// Broad native authority roots are never writable account home roots.
		path := root.GetPath()
		if path == "/" || path == "/etc" || path == "/usr" || path == "/var" || path == "/run" || path == "/root" || filepath.Clean(path) != path {
			return ErrUnsafe
		}
	}
	return nil
}

// rootDirectory requires a directory whose whole no-follow ancestry and leaf
// are root-owned without group/other write.
func rootDirectory(path string) error {
	file, stat, err := custody.OpenRoot(path, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return unsafe(err)
	}
	if err = file.Close(); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrUnsafe
	}
	return nil
}
func validateNativeTarget(ctx context.Context, p *Provider, r *agentv1.NativeResourceTransactionRequest, db *localDB) error {
	if err := validateMessage(r); err != nil {
		return err
	}
	if r.GetBefore().GetAccountPrivate() == nil || r.GetTarget().GetAccountPrivate() == nil || !proto.Equal(r.GetBefore().GetObservation().GetRef(), r.GetPlan().GetRef()) || !proto.Equal(r.GetTarget().GetObservation().GetRef(), r.GetPlan().GetRef()) {
		return ErrConflict
	}
	if r.GetOwnership().GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN || r.GetOwnership().GetEffectActionId() != r.GetActionId() {
		return ErrConflict
	}
	if !proto.Equal(r.GetOwnership().GetRef(), r.GetPlan().GetRef()) || r.GetOwnership().GetBeforeEffect() == nil || !sameTarget(r.GetOwnership().GetBeforeEffect(), r.GetBefore()) {
		return ErrConflict
	}
	d := resource.PlanDesired(r.Plan)
	// Every absent operation must be backed by ownership of the created object;
	// adoption of dimensions is not ownership of the entire native account.
	l := proto.CloneOf(r.Ownership)
	l.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED
	expected, edges, err := p.target(ctx, d, r.Plan.GetOperation(), r.Before, db, l)
	if err != nil {
		return err
	}
	if !sameTarget(expected, r.Target) {
		return ErrConflict
	}
	if r.Plan.GetLocalUser() != nil && r.Plan.GetLocalUser().GetCreateHome() != needsHome(expected) {
		return ErrConflict
	}
	planned := r.Plan.GetLocalGroup().GetMemberEdges()
	if r.Plan.GetLocalUser() != nil {
		planned = r.Plan.GetLocalUser().GetMemberEdges()
	}
	if len(edges) != len(planned) {
		return ErrConflict
	}
	for i := range edges {
		if !proto.Equal(edges[i], planned[i]) {
			return ErrConflict
		}
	}
	if r.Plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		digest, err := inverseDigest(expected, l.GetBaseline(), p.config.NativeDigest)
		if err != nil {
			return err
		}
		inverse := r.Plan.GetLocalGroup().GetInverse()
		if r.Plan.GetLocalUser() != nil {
			inverse = r.Plan.GetLocalUser().GetInverse()
		}
		if !bytes.Equal(digest, inverse.GetInverseSha256()) {
			return ErrConflict
		}
	}
	return nil
}
func sameTarget(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	a = proto.CloneOf(a)
	b = proto.CloneOf(b)
	a.Observation.Metadata = nil
	b.Observation.Metadata = nil
	a.AccountMemberEdges = nil
	b.AccountMemberEdges = nil
	if a.AccountPrivate != nil {
		a.AccountPrivate.EncryptedPasswordToken = nil
	}
	if b.AccountPrivate != nil {
		b.AccountPrivate.EncryptedPasswordToken = nil
	}
	return proto.Equal(a, b)
}

// checkNative is a read-only launcher prerequisite; it does not authorize effects.
func checkNative(ctx context.Context, c nativeConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.Native == nil || c.Platform == nil || c.ExecutorIncarnation == "" {
		return ErrUnsupported
	}
	if err := validateNativeConfig(c.Native); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks("/etc/os-release")
	if err != nil {
		return err
	}
	data, err := rootRead(resolved)
	if err != nil {
		return err
	}
	fields := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[key] = strings.Trim(value, "\"'")
		}
	}
	if fields["ID"] != c.Platform.GetOsId() || fields["VERSION_ID"] != c.Platform.GetVersion() {
		return ErrConflict
	}
	for _, marker := range []string{"/run/ostree-booted", "/etc/NIXOS", "/etc/transactional-update.conf"} {
		if _, err := os.Stat(marker); err == nil {
			return ErrUnsupported
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return checkHooks()
}
