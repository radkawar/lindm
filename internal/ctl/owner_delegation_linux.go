// SPDX-License-Identifier: Apache-2.0

package ctl

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
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
	"lindm/internal/custody"
	"lindm/internal/resource"
	"lindm/internal/serverops"
	"lindm/internal/trust"
)

const ownerDelegationUsage = "usage: lindmctl execution delegation sign -root FILE -bootstrap FILE -declaration FILE {-custody-export-file FILE -custody-passphrase-fd N [-signer-custody FILE ...] | -custodian-identity-file FILE -custodian-identity-passphrase-fd N -signer-custody FILE ...} -previous-version N -minimum-recovery-epoch N -out NEW_FILE"

type ownerDelegationInput struct {
	root, bootstrap, declaration, output string
	previous, epoch                      uint64
	custody                              serverops.CustodySigningOptions
	custodyFD, identityFD                int
}

// runOwnerDelegation deliberately bypasses CLI login/configuration and networking.
// The root is an authenticated owner input, never learned from the declaration.
func runOwnerDelegation(ctx context.Context, args []string, stdout io.Writer, clock func() time.Time) error {
	input, err := parseOwnerDelegation(args)
	if err != nil {
		return err
	}
	if err := custody.LockSecretMemory(); err != nil {
		return err
	}
	return signOwnerDelegation(ctx, &input, stdout, clock)
}

func parseOwnerDelegation(args []string) (input ownerDelegationInput, err error) {
	if len(args) < 2 || args[0] != "delegation" || args[1] != "sign" {
		return input, errors.New(ownerDelegationUsage)
	}
	flags := flag.NewFlagSet("execution delegation sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&input.root, "root", "", "protected pinned ExecutionRoot protobuf JSON")
	flags.StringVar(&input.bootstrap, "bootstrap", "", "protected root-quorum signed BootstrapBundle DSSE")
	flags.StringVar(&input.declaration, "declaration", "", "protected strict ExecutionDelegation protobuf JSON; exact roles and capabilities")
	flags.StringVar(&input.output, "out", "", "new DSSE envelope file; never replaces existing output")
	flags.Uint64Var(&input.previous, "previous-version", 0, "last accepted deployment-global delegation version (explicitly 0 for first issuance)")
	flags.Uint64Var(&input.epoch, "minimum-recovery-epoch", 0, "last accepted recovery epoch (explicitly 0 for first issuance)")
	flags.StringVar(&input.custody.ExportFile, "custody-export-file", "", "off-host passphrase-encrypted generated custodian export")
	flags.IntVar(&input.custodyFD, "custody-passphrase-fd", -1, "owner-private anonymous passphrase pipe")
	flags.StringVar(&input.custody.IdentityFile, "custodian-identity-file", "", "separately encrypted standard age custodian identity")
	flags.IntVar(&input.identityFD, "custodian-identity-passphrase-fd", -1, "owner-private anonymous custodian passphrase pipe")
	flags.Func("signer-custody", "encrypted root-key age object; repeat for external custodians or rotated keys", func(path string) error {
		if path == "" {
			return errors.New("missing encrypted signer")
		}
		input.custody.KeyFiles = append(input.custody.KeyFiles, path)
		return nil
	})
	if err := flags.Parse(args[2:]); err != nil {
		return input, errors.New("invalid offline owner flags; " + ownerDelegationUsage)
	}
	seen := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	if flags.NArg() != 0 || input.root == "" || input.bootstrap == "" || input.declaration == "" || input.output == "" ||
		(input.custody.ExportFile == "") == (input.custody.IdentityFile == "") || (input.custody.IdentityFile != "" && len(input.custody.KeyFiles) == 0) ||
		(input.custody.ExportFile != "" && input.custodyFD < 0) || (input.custody.IdentityFile != "" && input.identityFD < 0) ||
		!seen["previous-version"] || !seen["minimum-recovery-epoch"] {
		return input, errors.New(ownerDelegationUsage)
	}
	return input, nil
}

func signOwnerDelegation(ctx context.Context, input *ownerDelegationInput, stdout io.Writer, clock func() time.Time) error {
	rootJSON, err := readOwnerDocument(input.root)
	if err != nil {
		return errors.New("read protected owner root failed")
	}
	bootstrapEnvelope, err := readOwnerDocument(input.bootstrap)
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
	data, err := readOwnerDocument(input.declaration)
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
	keys, err := loadOwnerDelegationKeys(ctx, bootstrap.Root, input.custody, input.custodyFD, input.identityFD)
	if err != nil {
		return err
	}
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	envelope, err := authority.Sign(ctx, declaration, keys...)
	if err != nil {
		return fmt.Errorf("sign owner delegation: %w", err)
	}
	// Prove quorum, domain separation, roles, identity, validity and rollback
	// fences through the same verifier used by production before publishing.
	verified, err := verifier.VerifyDelegation(ctx, bootstrap.Root, envelope, input.previous, input.epoch, now)
	if err != nil {
		return fmt.Errorf("verify signed owner delegation: %w", err)
	}
	if err := protovalidate.Validate(&agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: envelope}); err != nil {
		return errors.New("signed delegation exceeds the production trust-update contract")
	}
	if err := printOwnerDelegation(stdout, verified, envelope, bootstrap.Root.GetThreshold(), len(keys)); err != nil {
		return err
	}
	if err := publishOwnerDelegation(input.output, envelope); err != nil {
		return fmt.Errorf("publish owner delegation without replacement: %w", err)
	}
	_, err = fmt.Fprintln(stdout, "Published verified DSSE delegation. No existing authority was changed or installed.")
	return err
}

func loadOwnerDelegationKeys(ctx context.Context, root *agentv1.ExecutionRoot, options serverops.CustodySigningOptions, custodyFD, custodianFD int) ([]ed25519.PrivateKey, error) {
	if options.ExportFile != "" {
		passphrase, err := custody.ReadPassphraseFD(ctx, custodyFD, false)
		if err != nil {
			return nil, err
		}
		options.Passphrase = passphrase
		defer clear(passphrase)
	}
	if options.IdentityFile != "" {
		passphrase, err := custody.ReadPassphraseFD(ctx, custodianFD, false)
		if err != nil {
			return nil, err
		}
		options.IdentityPassphrase = passphrase
		defer clear(passphrase)
	}
	return serverops.LoadCustodySigningKeys(ctx, options, root)
}

func ownerCapabilities(declaration *agentv1.ExecutionDelegation) error {
	// Derive the supported device-action and resource sets from the actual typed
	// mappings, rather than maintaining a second list that can silently omit one.
	supported := map[string]bool{trust.OfflineEnrollmentCapability: true, trust.CapabilityPolicyCapability: true}
	for _, kind := range resource.ExecutableKinds() {
		capability, err := resource.Capability(kind)
		if err != nil {
			return errors.New("resource kind has no supported delegation capability")
		}
		supported[capability] = true
	}
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
