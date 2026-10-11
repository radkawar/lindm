//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"time"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

const redHatGuestOwner = "/var/tmp/lindm-native-lab/redhat-registration-owned"
const redHatConsumerCertificate = "/etc/pki/consumer/cert.pem"

// Execute the installed subscription-manager entrypoint, not a reimplementation
// of RHSM. Its CLI parser receives in-memory arguments: /proc, exec audit, SSH,
// sudo and process diagnostics see only this constant script and the operation.
// Disable Python logging before RHSM initializes its logger; neither native
// diagnostics nor the activation-key request may enter rhsm.log or journald.
const redHatSubscriptionScript = `import json, logging, resource, runpy, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
logging.disable(sys.maxsize)
operation = sys.argv[1]
sys.argv = ["/usr/sbin/subscription-manager", operation]
if operation == "register":
    material = json.load(sys.stdin)
    sys.argv += ["--org", material["organization_id"], "--activationkey", material["activation_key"], "--name", material["run_name"]]
    del material
runpy.run_path("/usr/sbin/subscription-manager", run_name="__main__")
`

const redHatRepositoriesScript = `import logging, resource, runpy, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
logging.disable(sys.maxsize)
sys.argv = ["/usr/bin/dnf"] + sys.argv[1:]
runpy.run_path("/usr/bin/dnf", run_name="__main__")
`

func guestRedHat(ctx context.Context, operation string) error {
	if os.Geteuid() != 0 {
		return errors.New("redhat guest registration requires root")
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return errors.New("cannot protect Red Hat guest registration memory")
	}
	timeout := 100 * time.Second
	if operation == "redhat-repositories" {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch operation {
	case "redhat-ready":
		for _, path := range []string{redHatGuestOwner, redHatConsumerCertificate, "/etc/pki/consumer/key.pem"} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return errors.New("refusing a preexisting Red Hat guest registration or ownership marker")
			}
		}
		return nil
	case "redhat-register":
		payload, err := readRedHatGuestInput(ctx)
		if err != nil {
			return err
		}
		defer clear(payload)
		if _, err := os.Lstat(redHatConsumerCertificate); !errors.Is(err, os.ErrNotExist) {
			return errors.New("refusing to replace an existing Red Hat guest consumer")
		}
		owner, err := os.OpenFile(redHatGuestOwner, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("cannot claim disposable Red Hat guest registration")
		}
		if err := owner.Close(); err != nil {
			return errors.New("cannot close Red Hat guest ownership marker")
		}
		if err := runRedHatSubscription(ctx, "register", payload); err != nil {
			return err
		}
		credentials := new(labv1.RedHatRegistrationCredentials)
		defer proto.Reset(credentials)
		if err := protojson.Unmarshal(payload, credentials); err != nil {
			return errors.New("cannot recover validated Red Hat registration name")
		}
		certificate, err := os.ReadFile(redHatConsumerCertificate)
		if err != nil {
			return errors.New("cannot read native Red Hat consumer certificate")
		}
		defer clear(certificate)
		identity, err := redHatCertificateIdentity(certificate, credentials.GetRunName())
		if err != nil {
			return err
		}
		output, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(identity)
		if err != nil {
			return errors.New("cannot encode public Red Hat consumer identity")
		}
		if _, err := os.Stdout.Write(output); err != nil {
			return errors.New("cannot deliver public Red Hat consumer identity")
		}
		return nil
	case "redhat-unregister":
		if _, err := os.Lstat(redHatGuestOwner); errors.Is(err, os.ErrNotExist) {
			return nil // Registration never crossed the owned mutation boundary.
		} else if err != nil {
			return errors.New("cannot inspect Red Hat guest ownership")
		}
		if _, err := os.Lstat(redHatConsumerCertificate); err != nil {
			return errors.New("owned Red Hat consumer certificate unavailable; unregistration cannot be established")
		}
		if err := runRedHatSubscription(ctx, "unregister", nil); err != nil {
			return err
		}
		if err := os.Remove(redHatGuestOwner); err != nil {
			return errors.New("cannot retire Red Hat guest ownership")
		}
		return nil
	case "redhat-identity":
		return runRedHatSubscription(ctx, "identity", nil)
	case "redhat-repositories":
		output := nativeexec.NewBuffer(16 << 10)
		defer func() { clear(output.Bytes()) }()
		if err := redHatGuest(ctx, nil, output, "-c", redHatRepositoriesScript, "-q", "repolist", "--enabled"); err != nil || output.Truncated() {
			return errors.New("redhat enabled repository observation failed (native output suppressed)")
		}
		// Refuse an empty repository set; makecache alone can succeed without
		// repositories. Suppress native logs as well as command output.
		if !redHatEnabledRepositories(output.Bytes()) {
			return errors.New("redhat guest has no enabled repositories")
		}
		if err := redHatGuest(ctx, nil, nil, "-c", redHatRepositoriesScript, "-q", "--setopt=*.skip_if_unavailable=False", "--refresh", "makecache"); err != nil {
			return errors.New("redhat repository metadata refresh failed (native output suppressed)")
		}
		return nil
	default:
		return errors.New("unknown Red Hat guest operation")
	}
}

func redHatEnabledRepositories(data []byte) bool {
	header := false
	for line := range bytes.SplitSeq(data, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) == 4 && bytes.Equal(fields[0], []byte("repo")) && bytes.Equal(fields[1], []byte("id")) && bytes.Equal(fields[2], []byte("repo")) && bytes.Equal(fields[3], []byte("name")) {
			header = true
			continue
		}
		if header && len(fields) >= 2 {
			return true
		}
	}
	return false
}

// redHatGuest runs the guest's python3 with a fixed environment. Nil stdout
// goes directly to /dev/null and stderr always does, never to a diagnostic buffer.
func redHatGuest(ctx context.Context, stdin io.Reader, stdout io.Writer, args ...string) error {
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
	return labexec.Run(ctx, labexec.Command{Path: "/usr/bin/python3", Args: args, Env: env, Stdin: stdin, Stdout: stdout})
}

func runRedHatSubscription(ctx context.Context, operation string, payload []byte) error {
	if err := redHatGuest(ctx, bytes.NewReader(payload), nil, "-c", redHatSubscriptionScript, operation); err != nil {
		return errors.New("redhat subscription-manager operation failed (native output suppressed)")
	}
	return nil
}

func redHatCertificateIdentity(data []byte, runName string) (*labv1.RedHatRegistrationIdentity, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid native Red Hat consumer certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid native Red Hat consumer certificate")
	}
	// RHSM's consumer identity certificate uses the consumer UUID as its CN.
	// Never expose the remaining certificate subject (which contains account data).
	identity := &labv1.RedHatRegistrationIdentity{RunName: runName, ConsumerUuid: certificate.Subject.CommonName}
	if err := protovalidate.Validate(identity); err != nil {
		return nil, errors.New("invalid native Red Hat consumer identity")
	}
	return identity, nil
}

func decodeRedHatGuestInput(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > 4096 {
		return nil, errors.New("redhat guest stdin must contain at most 4096 bytes of protobuf JSON")
	}
	credentials := new(labv1.RedHatRegistrationCredentials)
	defer proto.Reset(credentials)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, credentials); err != nil {
		return nil, errors.New("invalid Red Hat registration protobuf JSON")
	}
	if err := protovalidate.Validate(credentials); err != nil {
		return nil, errors.New("invalid Red Hat registration credentials")
	}
	payload, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(credentials)
	if err != nil {
		return nil, errors.New("cannot encode ephemeral Red Hat registration input")
	}
	return payload, nil
}

func readRedHatGuestInput(ctx context.Context) ([]byte, error) {
	fd, err := unix.FcntlInt(os.Stdin.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("cannot duplicate Red Hat registration stdin")
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, errors.New("cannot prepare Red Hat registration stdin")
	}
	input := os.NewFile(uintptr(fd), "redhat-registration-stdin")
	defer func() { _ = input.Close() }()
	deadline := time.Now().Add(30 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := input.SetReadDeadline(deadline); err != nil {
		info, statErr := input.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			return nil, errors.New("redhat registration stdin must support a bounded read")
		}
	}
	data, err := io.ReadAll(io.LimitReader(input, 4097))
	defer clear(data)
	if err != nil {
		return nil, errors.New("cannot read Red Hat registration stdin")
	}
	return decodeRedHatGuestInput(data)
}
