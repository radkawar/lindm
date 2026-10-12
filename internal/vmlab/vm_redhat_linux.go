//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
	"lindm/internal/redhatimages"
)

// VMRedHatEvidence contains public identity and outcomes, never account or key data.
type VMRedHatEvidence struct {
	RunName                     string `json:"run_name"`
	ConsumerUUID                string `json:"consumer_uuid,omitempty"`
	ReceiptPath                 string `json:"receipt_path"`
	Registered                  bool   `json:"registered"`
	IdentityObserved            bool   `json:"identity_observed"`
	RepositoryMetadataRefreshed bool   `json:"repository_metadata_refreshed"`
	Unregistered                bool   `json:"unregistered"`
	ActivationKeyDeleted        bool   `json:"activation_key_deleted"`
}

type vmRedHatRegistration struct {
	vm       *guestVM
	client   *redhatimages.Client
	lease    *redhatimages.Registration
	evidence *VMRedHatEvidence
}

func validateVMRedHatToken(release *platform.Release, tokenFile string) error {
	if tokenFile != "" && !release.Lab.Entitlement {
		return errors.New("-redhat-token-file is only valid for subscription-entitled (RHEL) guests")
	}
	return nil
}

// The native package lane uses offline, already satisfied RPM dependencies. A
// token is optional there; any future repository installation must require one.
// The probe must already be uploaded before this function is called.
func registerVMRedHat(ctx context.Context, vm *guestVM, tokenFile string, evidence *VMRedHatEvidence) (_ *vmRedHatRegistration, err error) {
	if tokenFile == "" {
		return nil, nil
	}
	if err := runVMRedHatProbe(ctx, vm, "redhat-ready", nil, nil); err != nil {
		return nil, err
	}
	client, err := redhatimages.New(ctx, tokenFile)
	if err != nil {
		return nil, err
	}
	registration := &vmRedHatRegistration{vm: vm, client: client, evidence: evidence}
	defer func() {
		if err != nil {
			err = errors.Join(err, registration.Close())
		}
	}()
	runName, err := newVMRedHatRunName()
	if err != nil {
		return nil, err
	}
	evidence.RunName = runName
	receipt, err := createVMRedHatReceipt(filepath.Dir(vm.dir), runName)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, receipt.Close()) }()
	evidence.ReceiptPath = receipt.Name()
	registration.lease, err = client.CreateRegistration(ctx)
	if err != nil {
		return nil, err
	}
	organization, key := registration.lease.Credentials()
	credentials := &labv1.RedHatRegistrationCredentials{OrganizationId: organization, ActivationKey: key, RunName: runName}
	payload, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(credentials)
	credentials.OrganizationId, credentials.ActivationKey = "", ""
	if err != nil {
		return nil, errors.New("encode ephemeral Red Hat registration input")
	}
	defer clear(payload)
	identity := &labv1.RedHatRegistrationIdentity{RunName: runName}
	if err := runVMRedHatProbe(ctx, vm, "redhat-register", payload, identity); err != nil {
		return nil, err
	}
	evidence.Registered = true
	evidence.ConsumerUUID = identity.GetConsumerUuid()
	// Persist the exact native UUID before any subsequent guest operation.
	if err := appendVMRedHatReceipt(receipt, identity); err != nil {
		return nil, err
	}
	if err := runVMRedHatProbe(ctx, vm, "redhat-identity", nil, nil); err != nil {
		return nil, err
	}
	evidence.IdentityObserved = true
	if err := runVMRedHatProbe(ctx, vm, "redhat-repositories", nil, nil); err != nil {
		return nil, err
	}
	evidence.RepositoryMetadataRefreshed = true
	return registration, nil
}

func runVMRedHatProbe(ctx context.Context, vm *guestVM, operation string, payload []byte, identity *labv1.RedHatRegistrationIdentity) error {
	// Never retain even unexpected output in opt-in failure diagnostics. The
	// guest additionally discards native stdout/stderr and disables RHSM logging.
	capture := vm.captureDiagnostics
	vm.captureDiagnostics = false
	defer func() { vm.captureDiagnostics = capture }()
	timeout := 2 * time.Minute
	if operation == "redhat-repositories" {
		// Beyond the guest probe's own 20-minute metadata refresh bound.
		timeout = 21 * time.Minute
	}
	result, err := vm.runResult(ctx, "sudo -n "+guestLifecycleProbe+" guest "+operation, bytes.NewReader(payload), 1024, timeout)
	defer clear(result.Stdout)
	defer clear(result.Stderr)
	if err != nil || result.ExitCode != 0 || len(result.Stderr) != 0 {
		reason := "credentials and native output suppressed"
		if fixed, ok := bytes.CutPrefix(bytes.TrimSuffix(result.Stderr, []byte("\n")), []byte("lab: ")); ok {
			for _, known := range vmRedHatGuestReasons {
				if bytes.Equal(fixed, []byte(known)) {
					reason = known
				}
			}
		}
		return errors.New("redhat guest " + operation + " failed (" + reason + ")")
	}
	if identity != nil {
		decoded, err := decodeVMRedHatIdentity(result.Stdout, identity.GetRunName())
		if err != nil {
			return err
		}
		identity.ConsumerUuid = decoded.GetConsumerUuid()
	} else if len(result.Stdout) != 0 {
		return errors.New("redhat guest " + operation + " failed (unexpected output suppressed)")
	}
	return nil
}

// vmRedHatGuestReasons are the guest probe's fixed, secret-free refusals that
// distinguish repository failures; any other guest output stays suppressed.
var vmRedHatGuestReasons = []string{
	"redhat enabled repository observation failed (native output suppressed)",
	"redhat guest has no enabled repositories",
	"redhat repository metadata refresh failed (native output suppressed)",
}

var vmRedHatRunNamePattern = regexp.MustCompile(`^lindm-lab-[0-9a-f]{32}$`)

func newVMRedHatRunName() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", errors.New("cannot generate public Red Hat run identity")
	}
	return "lindm-lab-" + hex.EncodeToString(random[:]), nil
}

func decodeVMRedHatIdentity(data []byte, runName string) (*labv1.RedHatRegistrationIdentity, error) {
	identity := new(labv1.RedHatRegistrationIdentity)
	if len(data) == 0 || len(data) > 1024 {
		return nil, errors.New("invalid public Red Hat registration receipt")
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, identity); err != nil {
		return nil, errors.New("invalid public Red Hat registration receipt")
	}
	if err := protovalidate.Validate(identity); err != nil || identity.GetRunName() != runName {
		return nil, errors.New("invalid public Red Hat registration identity")
	}
	return identity, nil
}

func createVMRedHatReceipt(directory, runName string) (*os.File, error) {
	// The receipt lives alongside, never inside, disposable VM state. Publish
	// the independent name before mutation, covering a lost registration reply.
	identity := &labv1.RedHatRegistrationIdentity{RunName: runName}
	if !vmRedHatRunNamePattern.MatchString(runName) {
		return nil, errors.New("invalid public Red Hat receipt name")
	}
	file, err := os.OpenFile(filepath.Join(directory, runName+".redhat-registration.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0600)
	if err != nil {
		return nil, errors.New("cannot create private Red Hat registration receipt")
	}
	if err := appendVMRedHatReceipt(file, identity); err != nil {
		_ = file.Close()
		return nil, err
	}
	dir, err := os.Open(directory)
	if err != nil {
		_ = file.Close()
		return nil, errors.New("cannot open Red Hat registration receipt directory")
	}
	if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
		_ = file.Close()
		return nil, errors.New("cannot persist Red Hat registration receipt directory")
	}
	return file, nil
}

func appendVMRedHatReceipt(file *os.File, identity *labv1.RedHatRegistrationIdentity) error {
	data, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(identity)
	if err != nil {
		return errors.New("cannot encode public Red Hat registration receipt")
	}
	data = append(data, '\n')
	if _, err := file.Write(data); err != nil {
		return errors.New("cannot write private Red Hat registration receipt")
	}
	if err := file.Sync(); err != nil {
		return errors.New("cannot persist private Red Hat registration receipt")
	}
	return nil
}

func (r *vmRedHatRegistration) Close() error {
	if r == nil {
		return nil
	}
	defer r.client.Close()
	if r.lease == nil {
		return nil
	}
	return cleanupVMRedHat(func(ctx context.Context) error {
		// A cancelled SSH operation closes its transport. Always acquire a fresh
		// pinned connection, while QEMU and the uploaded probe are still owned.
		if r.vm.client != nil {
			_ = r.vm.client.Close()
		}
		if err := r.vm.connect(ctx); err != nil {
			return errors.New("redhat guest cleanup could not reconnect")
		}
		if err := runVMRedHatProbe(ctx, r.vm, "redhat-unregister", nil, nil); err != nil {
			return err
		}
		r.evidence.Unregistered = true
		return nil
	}, func(ctx context.Context) error {
		if err := r.lease.Close(ctx); err != nil {
			return err
		}
		r.evidence.ActivationKeyDeleted = true
		return nil
	})
}

// A failed or cancelled unregister must not skip key deletion. Each operation
// gets its own independent deadline, so an unreachable guest cannot exhaust the
// hosted cleanup deadline. Both errors remain visible to the caller.
func cleanupVMRedHat(unregister, deleteKey func(context.Context) error) error {
	guestCtx, cancelGuest := context.WithTimeout(context.Background(), 3*time.Minute)
	guestErr := unregister(guestCtx)
	cancelGuest()
	keyCtx, cancelKey := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelKey()
	return errors.Join(guestErr, deleteKey(keyCtx))
}
