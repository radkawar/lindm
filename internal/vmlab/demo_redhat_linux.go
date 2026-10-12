//go:build linux

package vmlab

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/redhatimages"
)

// demoRedHatReceiptSuffix names the private receipt kept in the device root,
// beside (never inside) the encrypted VM state, until explicit destruction.
const demoRedHatReceiptSuffix = ".redhat-registration.jsonl"

// A real organization's RHEL server is registered: CSAF matching needs the
// servicing stream that only its entitled repositories corroborate. Unlike a
// disposable lane, the consumer outlives each run and is removed by exact
// UUID on destroy. The single-use activation key is deleted immediately.
// record durably stores the identity on the controller: the run name before
// Red Hat is contacted, then its consumer before any further guest operation.
func registerDemoRedHat(ctx context.Context, vm *guestVM, root, tokenFile, labBinary string, record func(context.Context, *labv1.RedHatRegistrationIdentity) error) (err error) {
	identity, err := readDemoRedHatReceipt(root)
	if err != nil {
		return err
	}
	if identity != nil {
		if identity.GetConsumerUuid() == "" {
			return fmt.Errorf("red hat registration %s recorded no consumer; destroy the device explicitly", identity.GetRunName())
		}
		return nil
	}
	if tokenFile == "" {
		return errors.New("entitled organization device requires -redhat-token-file")
	}
	if record == nil {
		return errors.New("entitled organization device requires its controller's registration record")
	}
	if err := lifecycleCommand(ctx, vm, "stage registration probe directory", "install -d -m 0755 "+nativeGuestDir); err != nil {
		return err
	}
	if err := uploadLifecycleProbe(ctx, vm, labBinary); err != nil {
		return err
	}
	if err := runVMRedHatProbe(ctx, vm, "redhat-ready", nil, nil); err != nil {
		return err
	}
	client, err := redhatimages.New(ctx, tokenFile)
	if err != nil {
		return err
	}
	defer client.Close()
	runName, err := newVMRedHatRunName()
	if err != nil {
		return err
	}
	// The controller holds the run name before this host's receipt and any
	// Red Hat contact, so it refuses a lost registration reply too. Without a
	// receipt nothing was registered, and a later start records a new name.
	if err := record(ctx, &labv1.RedHatRegistrationIdentity{RunName: runName}); err != nil {
		return fmt.Errorf("record red hat registration %s on the controller: %w", runName, err)
	}
	receipt, err := createVMRedHatReceipt(root, runName)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, receipt.Close()) }()
	lease, err := client.CreateRegistration(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		err = errors.Join(err, lease.Close(cleanup))
	}()
	organization, key := lease.Credentials()
	credentials := &labv1.RedHatRegistrationCredentials{OrganizationId: organization, ActivationKey: key, RunName: runName}
	payload, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(credentials)
	credentials.OrganizationId, credentials.ActivationKey = "", ""
	if err != nil {
		return errors.New("encode ephemeral Red Hat registration input")
	}
	defer clear(payload)
	registered := &labv1.RedHatRegistrationIdentity{RunName: runName}
	if err := runVMRedHatProbe(ctx, vm, "redhat-register", payload, registered); err != nil {
		return err
	}
	// Persist the exact consumer before any other guest operation: first in
	// this host's receipt, then on the controller, which can remove it while
	// this host is unreachable.
	if err := appendVMRedHatReceipt(receipt, registered); err != nil {
		return err
	}
	if err := record(ctx, registered); err != nil {
		return fmt.Errorf("record red hat consumer %s (%s) on the controller: %w", registered.GetConsumerUuid(), runName, err)
	}
	if err := runVMRedHatProbe(ctx, vm, "redhat-identity", nil, nil); err != nil {
		return err
	}
	if err := runVMRedHatProbe(ctx, vm, "redhat-repositories", nil, nil); err != nil {
		return err
	}
	// Entitled repositories replace the pre-registration DVD dependency source.
	return lifecycleCommand(ctx, vm, "retire pre-registration DVD repositories", "rm -f /etc/yum.repos.d/lindm-vendor-media.repo; if systemctl cat mnt-lindmvendor.mount >/dev/null 2>&1; then systemctl --quiet disable --now mnt-lindmvendor.mount; rm -f /etc/systemd/system/mnt-lindmvendor.mount; systemctl daemon-reload; fi")
}

// demoRedHatRegistered reports whether the device root records a registration.
func demoRedHatRegistered(root string) (bool, error) {
	identity, err := readDemoRedHatReceipt(root)
	return identity != nil, err
}

// readDemoRedHatReceipt returns the latest recorded identity of the device's
// single registration, or nil when it was never registered.
func readDemoRedHatReceipt(root string) (_ *labv1.RedHatRegistrationIdentity, err error) {
	matches, err := filepath.Glob(filepath.Join(root, "lindm-lab-*"+demoRedHatReceiptSuffix))
	if err != nil || len(matches) == 0 {
		return nil, err
	}
	if len(matches) > 1 {
		return nil, errors.New("device root records more than one Red Hat registration")
	}
	runName := strings.TrimSuffix(filepath.Base(matches[0]), demoRedHatReceiptSuffix)
	file, err := os.Open(matches[0])
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	var identity *labv1.RedHatRegistrationIdentity
	scanner := bufio.NewScanner(io.LimitReader(file, 16<<10))
	for scanner.Scan() {
		line := new(labv1.RedHatRegistrationIdentity)
		if err := protojson.Unmarshal(scanner.Bytes(), line); err != nil || line.GetRunName() != runName {
			return nil, errors.New("invalid Red Hat registration receipt")
		}
		// The first line names the run before registration; a consumer line
		// must be a complete, valid public identity.
		if line.GetConsumerUuid() != "" {
			if line, err = decodeVMRedHatIdentity(scanner.Bytes(), runName); err != nil {
				return nil, err
			}
		}
		if identity == nil || line.GetConsumerUuid() != "" {
			identity = line
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, errors.New("empty Red Hat registration receipt")
	}
	return identity, nil
}

// UnregisterDemoRedHat removes a stopped organization device's recorded RHSM
// consumer by exact UUID before its VM is deleted, then retires the receipt.
// An unrecorded consumer (lost registration reply) is refused, never guessed.
func UnregisterDemoRedHat(ctx context.Context, root, tokenFile string, stdout io.Writer) error {
	identity, err := readDemoRedHatReceipt(root)
	if err != nil || identity == nil {
		return err
	}
	if identity.GetConsumerUuid() == "" {
		return fmt.Errorf("red hat registration %s recorded no consumer UUID; remove it with the maintained laboratory registration cleanup before destroying", identity.GetRunName())
	}
	if tokenFile == "" {
		return errors.New("destroying a registered organization device requires -redhat-token-file")
	}
	client, err := redhatimages.New(ctx, tokenFile)
	if err != nil {
		return err
	}
	defer client.Close()
	removal, err := client.RemoveSystem(ctx, identity.GetConsumerUuid(), identity.GetRunName())
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "Unregistered Red Hat system %s (%s): deleted=%t absent=%t\n", removal.UUID, identity.GetRunName(), removal.Deleted, removal.Absent); err != nil {
		return err
	}
	return os.Remove(filepath.Join(root, identity.GetRunName()+demoRedHatReceiptSuffix))
}
