package ctl

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

const ownerDelegationUsage = "usage: lindmctl execution delegation sign -root FILE -bootstrap FILE -declaration FILE -signer FILE [-signer FILE ...] -previous-version N -minimum-recovery-epoch N -out NEW_FILE"

// runOwnerDelegation deliberately bypasses CLI login/configuration and networking.
// The root is an authenticated owner input, never learned from the declaration.
func runOwnerDelegation(ctx context.Context, args []string, stdout io.Writer, clock func() time.Time) error {
	if len(args) < 2 || args[0] != "delegation" || args[1] != "sign" {
		return errors.New(ownerDelegationUsage)
	}
	flags := flag.NewFlagSet("execution delegation sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	rootPath := flags.String("root", "", "protected pinned ExecutionRoot protobuf JSON")
	bootstrapPath := flags.String("bootstrap", "", "protected root-quorum signed BootstrapBundle DSSE")
	declarationPath := flags.String("declaration", "", "protected strict ExecutionDelegation protobuf JSON; exact roles and capabilities")
	outPath := flags.String("out", "", "new DSSE envelope file; never replaces existing output")
	previous := flags.Uint64("previous-version", 0, "last accepted deployment-global delegation version (explicitly 0 for first issuance)")
	epoch := flags.Uint64("minimum-recovery-epoch", 0, "last accepted recovery epoch (explicitly 0 for first issuance)")
	var signerPaths []string
	flags.Func("signer", "protected offline owner Ed25519 PKCS#8 PEM; repeat for quorum", func(path string) error {
		if path == "" {
			return errors.New("missing signer file")
		}
		signerPaths = append(signerPaths, path)
		return nil
	})
	if err := flags.Parse(args[2:]); err != nil {
		return errors.New("invalid offline owner flags; " + ownerDelegationUsage)
	}
	seen := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	if flags.NArg() != 0 || *rootPath == "" || *bootstrapPath == "" || *declarationPath == "" || *outPath == "" || len(signerPaths) == 0 || !seen["previous-version"] || !seen["minimum-recovery-epoch"] {
		return errors.New(ownerDelegationUsage)
	}
	rootJSON, err := readOwnerDocument(*rootPath)
	if err != nil {
		return errors.New("read protected owner root failed")
	}
	bootstrapEnvelope, err := readOwnerDocument(*bootstrapPath)
	if err != nil {
		return errors.New("read protected owner bootstrap failed")
	}
	authority, err := trust.New()
	if err != nil {
		return fmt.Errorf("initialize offline authority: %w", err)
	}
	now := clock()
	bootstrap, err := authority.VerifyBootstrap(ctx, rootJSON, bootstrapEnvelope, now)
	if err != nil {
		return fmt.Errorf("verify owner bootstrap: %w", err)
	}
	verifier, err := authority.NewExecutionVerifier(bootstrap)
	if err != nil {
		return fmt.Errorf("initialize production execution verifier: %w", err)
	}
	data, err := readOwnerDocument(*declarationPath)
	if err != nil {
		return errors.New("read protected delegation declaration failed")
	}
	declaration := new(agentv1.ExecutionDelegation)
	if err := protojson.Unmarshal(data, declaration); err != nil {
		return errors.New("declaration must be strict ExecutionDelegation protobuf JSON")
	}
	if err := protovalidate.Validate(declaration); err != nil {
		return errors.New("invalid ExecutionDelegation declaration")
	}
	if err := ownerCapabilities(declaration); err != nil {
		return err
	}
	// Never read more keys than the authenticated root can possibly authorize.
	if len(signerPaths) > len(bootstrap.Root.GetKeys()) {
		return errors.New("too many owner signer files for the pinned root")
	}
	keys := make([]ed25519.PrivateKey, 0, len(signerPaths))
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	for _, path := range signerPaths {
		key, err := readOwnerSigner(path)
		if err != nil {
			return err
		}
		keys = append(keys, key)
		id, err := trust.KeyID(ed25519.PublicKey(key[ed25519.SeedSize:]))
		if err != nil {
			return errors.New("invalid owner signer public key")
		}
		found := false
		for _, candidate := range bootstrap.Root.GetKeys() {
			if candidate.GetKeyId() == id {
				found = true
				break
			}
		}
		if !found {
			return errors.New("owner signer is not a member of the pinned execution root")
		}
	}
	envelope, err := authority.Sign(ctx, declaration, keys...)
	if err != nil {
		return fmt.Errorf("sign owner delegation: %w", err)
	}
	// Prove quorum, domain separation, roles, identity, validity and rollback
	// fences through the same verifier used by production before publishing.
	verified, err := verifier.VerifyDelegation(ctx, bootstrap.Root, envelope, *previous, *epoch, now)
	if err != nil {
		return fmt.Errorf("verify signed owner delegation: %w", err)
	}
	if err := protovalidate.Validate(&agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: envelope}); err != nil {
		return errors.New("signed delegation exceeds the production trust-update contract")
	}
	if err := printOwnerDelegation(stdout, verified, envelope, bootstrap.Root.GetThreshold(), len(keys)); err != nil {
		return err
	}
	if err := publishOwnerDelegation(*outPath, envelope); err != nil {
		return fmt.Errorf("publish owner delegation without replacement: %w", err)
	}
	_, err = fmt.Fprintln(stdout, "Published verified DSSE delegation. No existing authority was changed or installed.")
	return err
}

func ownerCapabilities(declaration *agentv1.ExecutionDelegation) error {
	// Derive the supported device-action set from the actual typed action mapping,
	// rather than maintaining a second list that can silently omit a new action.
	supported := map[string]bool{"systemd.service.v1": true, trust.OfflineEnrollmentCapability: true}
	spec := new(agentv1.DeviceActionSpec)
	message := spec.ProtoReflect()
	fields := message.Descriptor().Oneofs().ByName("action").Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		message.Set(field, message.NewField(field))
		capability, err := trust.DeviceActionCapability(spec)
		if err != nil {
			return errors.New("device action has no supported delegation capability")
		}
		supported[capability] = true
	}
	for _, delegate := range declaration.GetDelegates() {
		for _, capability := range delegate.GetCapabilities() {
			if !supported[capability] {
				return errors.New("declaration contains an unsupported exact capability")
			}
		}
	}
	return nil
}

func printOwnerDelegation(out io.Writer, declaration *agentv1.ExecutionDelegation, envelope []byte, threshold uint32, signatures int) error {
	var review strings.Builder
	fmt.Fprintf(&review, "Verified proposed delegation\nDeployment: %s\nRoot version: %d\nDelegation version: %d\nMinimum recovery epoch: %d\nValid from: %s\nExpires: %s\nOwner signatures: %d (required %d)\nDSSE SHA-256: %x\n", declaration.GetDeploymentId(), declaration.GetRootVersion(), declaration.GetVersion(), declaration.GetMinimumRecoveryEpoch(), declaration.GetNotBefore().AsTime().UTC().Format(time.RFC3339Nano), declaration.GetExpiresAt().AsTime().UTC().Format(time.RFC3339Nano), signatures, threshold, sha256.Sum256(envelope))
	if len(declaration.GetDelegates()) == 0 {
		review.WriteString("Delegates: none (revokes all online signer authority)\n")
	}
	for _, delegate := range declaration.GetDelegates() {
		fmt.Fprintf(&review, "Delegate: %s\n  Role: %s\n", delegate.GetKey().GetKeyId(), delegate.GetRole())
		for _, capability := range delegate.GetCapabilities() {
			fmt.Fprintf(&review, "  Capability: %s\n", capability)
		}
	}
	_, err := io.WriteString(out, review.String())
	return err
}

func readOwnerDocument(path string) (_ []byte, resultErr error) {
	store, err := openStore(path)
	if err != nil {
		return nil, errors.New("invalid protected owner directory")
	}
	defer func() { resultErr = errors.Join(resultErr, store.dir.Close()) }()
	fd, err := unix.Openat(int(store.dir.Fd()), store.name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("open protected owner file failed")
	}
	file := os.NewFile(uintptr(fd), store.name)
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, errors.New("inspect protected owner file failed")
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return nil, errors.New("owner input must be a singly linked regular file owned by this user with mode 0600")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDocumentBytes+1))
	if err != nil || len(data) > maxDocumentBytes {
		clear(data)
		return nil, errors.New("read bounded owner file failed")
	}
	return data, nil
}

func readOwnerSigner(path string) (ed25519.PrivateKey, error) {
	data, err := readOwnerDocument(path)
	if err != nil {
		return nil, errors.New("read protected owner signer failed")
	}
	defer clear(data)
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("owner signer must be one Ed25519 PKCS#8 PRIVATE KEY PEM block")
	}
	defer clear(block.Bytes)
	if !bytes.HasPrefix(data, []byte("-----BEGIN PRIVATE KEY-----")) || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("owner signer must be one Ed25519 PKCS#8 PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid owner signer PKCS#8 private key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("owner signer must use Ed25519")
	}
	return key, nil
}

func publishOwnerDelegation(path string, envelope []byte) (resultErr error) {
	store, err := openStore(path)
	if err != nil {
		return errors.New("invalid protected output directory")
	}
	defer func() { resultErr = errors.Join(resultErr, store.dir.Close()) }()
	fd := int(store.dir.Fd())
	suffix, err := randomToken()
	if err != nil {
		return err
	}
	name := ".delegation-" + suffix
	tmpFD, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("create delegation output failed")
	}
	file := os.NewFile(uintptr(tmpFD), name)
	defer func() {
		if err := unix.Unlinkat(fd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			resultErr = errors.Join(resultErr, errors.New("remove temporary delegation output failed"))
		}
	}()
	_, writeErr := file.Write(envelope)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return errors.New("write and sync delegation output failed")
	}
	if err := unix.Renameat2(fd, name, fd, store.name, unix.RENAME_NOREPLACE); err != nil {
		return errors.New("atomic delegation publication failed; output must not exist")
	}
	return store.dir.Sync()
}
