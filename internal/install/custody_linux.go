// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/custody"
	"lindm/internal/serverops"
)

// Custody recipients are separate cryptographic keys, not proof of independent
// humans. Quick start concentrates generated identities in one encrypted export.
type authorityCustody struct {
	recipients      [3]*age.X25519Recipient
	identities      []*agentv1.ServerRecoveryCustodianIdentity
	artifacts       []*agentv1.ServerRecoveryCustodyArtifact
	exportRecipient *age.ScryptRecipient
}

func newAuthorityCustody(ctx context.Context, o Options) (custody *authorityCustody, err error) {
	custody = &authorityCustody{}
	backup, err := protected(o.BackupRecipient, false)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{strings.TrimSpace(string(backup)): true}
	if len(o.ExecutionRootRecipients) > 3 {
		return nil, errors.New("at most three independent root custodian recipient files are accepted")
	}
	for i := range 3 {
		var recipient *age.X25519Recipient
		if i < len(o.ExecutionRootRecipients) {
			data, err := protected(o.ExecutionRootRecipients[i], false)
			if err != nil {
				return nil, err
			}
			recipient, err = age.ParseX25519Recipient(strings.TrimSpace(string(data)))
			if err != nil {
				return nil, errors.New("root custodian input must be an age X25519 public recipient")
			}
		} else {
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				return nil, err
			}
			recipient = identity.Recipient()
			custody.identities = append(custody.identities, &agentv1.ServerRecoveryCustodianIdentity{CustodianIndex: uint32(i + 1), PublicRecipient: recipient.String(), PrivateIdentity: identity.String()})
		}
		if seen[recipient.String()] {
			return nil, errors.New("root custodian recipients must be distinct from each other and from the backup recipient")
		}
		seen[recipient.String()] = true
		custody.recipients[i] = recipient
	}
	if len(custody.identities) > 0 {
		passphrase, err := readCustodyPassphrase(ctx, o.CustodyPassphraseFD)
		if err != nil {
			return nil, err
		}
		defer clear(passphrase)
		custody.exportRecipient, err = age.NewScryptRecipient(string(passphrase))
		if err != nil {
			return nil, errors.New("recovery custody passphrase could not be admitted")
		}
	}
	return custody, nil
}

func (c *authorityCustody) clear() {
	for _, identity := range c.identities {
		identity.PrivateIdentity = ""
	}
	c.identities = nil
	c.exportRecipient = nil
}

func (c *authorityCustody) encryptArtifact(name string, index uint32, plain []byte) error {
	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, c.recipients[index-1])
	if err != nil {
		return err
	}
	_, writeErr := w.Write(plain)
	if err := errors.Join(writeErr, w.Close()); err != nil {
		return err
	}
	data := encrypted.Bytes()
	if err := newFile(filepath.Join("/etc/lindm/offline", name), data, 0, 0, 0600); err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	c.artifacts = append(c.artifacts, &agentv1.ServerRecoveryCustodyArtifact{Name: name, CustodianIndex: index, Sha256: digest[:], EncryptedData: data})
	return nil
}

func (c *authorityCustody) sealRoot(index uint32, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer clear(der)
	plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(plain)
	return c.encryptArtifact(fmt.Sprintf("root-key-%d.age", index), index, plain)
}

func (c *authorityCustody) sealPKI(payload *agentv1.ServerRecoveryPKIExport) error {
	plain, err := protojson.Marshal(payload)
	if err != nil {
		return err
	}
	defer clear(plain)
	return c.encryptArtifact("sealed-pki-ca.age", 1, plain)
}

func (c *authorityCustody) export(o Options, deployment string, root *agentv1.ExecutionRoot, gid int) (err error) {
	if c.exportRecipient == nil {
		return nil
	}
	payload := &agentv1.ServerRecoveryCustodyExport{DeploymentId: deployment, PublicUrl: o.Origin, DevicePublicUrl: o.DeviceOrigin, ExecutionRoot: root, Identities: c.identities, Artifacts: c.artifacts}
	plain, err := protojson.Marshal(payload)
	if err != nil {
		return err
	}
	defer clear(plain)
	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, c.exportRecipient)
	if err != nil {
		return err
	}
	_, writeErr := w.Write(plain)
	if err := errors.Join(writeErr, w.Close()); err != nil {
		return err
	}
	return newFile(serverops.RecoveryCustodyBundlePath, encrypted.Bytes(), 0, gid, 0640)
}

// An explicit descriptor accepts an anonymous root-protected pipe, not a
// passphrase file. Interactive input is bounded and echo is always restored.
func readCustodyPassphrase(ctx context.Context, inputFD int) (passphrase []byte, err error) {
	// Run after terminal/descriptor cleanup: late cleanup errors must not return
	// a still-live secret buffer to an error caller.
	defer func() {
		if err != nil {
			clear(passphrase)
			passphrase = nil
		}
	}()
	if inputFD >= 0 {
		secret, readErr := custody.ReadPassphraseFD(ctx, inputFD, true)
		closeErr := unix.Close(inputFD)
		if err := errors.Join(readErr, closeErr); err != nil {
			clear(secret)
			return nil, err
		}
		return secret, nil
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("private terminal or --custody-passphrase-fd required for recovery custody")
	}
	closed := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { closed <- f.Close() })
	defer func() {
		if stop() {
			err = errors.Join(err, f.Close())
		} else {
			err = errors.Join(err, <-closed)
		}
	}()
	controlFD, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, unix.Close(controlFD)) }()
	terminal, err := unix.IoctlGetTermios(controlFD, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	private := *terminal
	private.Lflag &^= unix.ECHO | unix.ECHONL
	if err := unix.IoctlSetTermios(controlFD, unix.TCSETS, &private); err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, unix.IoctlSetTermios(controlFD, unix.TCSETS, terminal)) }()
	reader := bufio.NewReaderSize(f, 1026)
	read := func(prompt string) ([]byte, error) {
		if _, err := fmt.Fprint(f, prompt); err != nil {
			return nil, err
		}
		line, err := reader.ReadSlice('\n')
		if err != nil {
			clear(line)
			return nil, errors.New("custody passphrase requires a bounded newline-terminated input")
		}
		value := line[:len(line)-1]
		if len(value) < 20 || len(value) > 1024 || bytes.ContainsAny(value, "\x00\r\n") {
			clear(line)
			return nil, errors.New("custody passphrase must contain 20 to 1024 bytes without control separators; choose a strong unique phrase")
		}
		result := bytes.Clone(value)
		clear(line)
		return result, nil
	}
	first, err := read("Recovery custody passphrase (20+ bytes, unique; never store on this server): ")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			clear(first)
		}
	}()
	second, err := read("\nRepeat recovery custody passphrase: ")
	if err != nil {
		return nil, err
	}
	defer clear(second)
	if subtle.ConstantTimeCompare(first, second) != 1 {
		return nil, errors.New("recovery custody passphrases differ")
	}
	if _, err := fmt.Fprintln(f); err != nil {
		return nil, err
	}
	return first, nil
}

func printCustody(output io.Writer) error {
	if _, err := fmt.Fprintln(output, "Encrypted authority custody: /etc/lindm/offline (root only; transfer each artifact to its assigned custodian)."); err != nil {
		return err
	}
	if _, err := os.Lstat(serverops.RecoveryCustodyBundlePath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	_, err := fmt.Fprintf(output, "Move the encrypted recovery export off this host: %s\nKeep its passphrase separately. One export does not establish independent human custodians. Complete the owner's protected custody-transfer confirmation after transfer.\n", serverops.RecoveryCustodyBundlePath)
	return err
}
