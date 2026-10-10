//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/redhatimages"
)

// VMRedHatEvidence contains outcomes only, never account or activation-key data.
type VMRedHatEvidence struct {
	Registered                  bool `json:"registered"`
	IdentityObserved            bool `json:"identity_observed"`
	RepositoryMetadataRefreshed bool `json:"repository_metadata_refreshed"`
	Unregistered                bool `json:"unregistered"`
	ActivationKeyDeleted        bool `json:"activation_key_deleted"`
}

type vmRedHatRegistration struct {
	vm       *guestVM
	client   *redhatimages.Client
	lease    *redhatimages.Registration
	evidence *VMRedHatEvidence
}

func validateVMRedHatToken(distribution, tokenFile string) error {
	if tokenFile != "" && distribution != "rhel" {
		return errors.New("-redhat-token-file is only valid for RHEL guests")
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
	if err := runVMRedHatProbe(ctx, vm, "redhat-ready", nil); err != nil {
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
	registration.lease, err = client.CreateRegistration(ctx)
	if err != nil {
		return nil, err
	}
	organization, key := registration.lease.Credentials()
	credentials := &labv1.RedHatRegistrationCredentials{OrganizationId: organization, ActivationKey: key}
	payload, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(credentials)
	credentials.OrganizationId, credentials.ActivationKey = "", ""
	if err != nil {
		return nil, errors.New("encode ephemeral Red Hat registration input")
	}
	defer clear(payload)
	if err := runVMRedHatProbe(ctx, vm, "redhat-register", payload); err != nil {
		return nil, err
	}
	evidence.Registered = true
	if err := runVMRedHatProbe(ctx, vm, "redhat-identity", nil); err != nil {
		return nil, err
	}
	evidence.IdentityObserved = true
	if err := runVMRedHatProbe(ctx, vm, "redhat-repositories", nil); err != nil {
		return nil, err
	}
	evidence.RepositoryMetadataRefreshed = true
	return registration, nil
}

func runVMRedHatProbe(ctx context.Context, vm *guestVM, operation string, payload []byte) error {
	// Never retain even unexpected output in opt-in failure diagnostics. The
	// guest additionally discards native stdout/stderr and disables RHSM logging.
	capture := vm.captureDiagnostics
	vm.captureDiagnostics = false
	defer func() { vm.captureDiagnostics = capture }()
	timeout := 2 * time.Minute
	if operation == "redhat-repositories" {
		timeout = 6 * time.Minute
	}
	result, err := vm.runResult(ctx, "sudo -n "+guestLifecycleProbe+" guest "+operation, bytes.NewReader(payload), 1024, timeout)
	defer clear(result.Stdout)
	defer clear(result.Stderr)
	if err != nil || result.ExitCode != 0 || len(result.Stdout) != 0 || len(result.Stderr) != 0 {
		return errors.New("redhat guest " + operation + " failed (credentials and native output suppressed)")
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
		if err := runVMRedHatProbe(ctx, r.vm, "redhat-unregister", nil); err != nil {
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
