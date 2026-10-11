//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/protobuf/encoding/protojson"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/inventory"
)

const usage = `Usage: lindm-agent inspect
       lindm-agent verify-bootstrap -root FILE -bundle FILE
       lindm-agent executor
       lindm-agent run
       lindm-agent session [-socket FILE]
       lindm-agent bootstrap -root FILE -bundle FILE -grant FILE
       lindm-agent bootstrap -root FILE -bundle FILE -provisioning-token-file FILE
       lindm-agent offline-export -root FILE -bundle FILE -file AUTHORIZATION -out REQUEST
       lindm-agent offline-export -resume -out REQUEST
       lindm-agent offline-import -file RESPONSE
       lindm-agent resume [-wait-seconds SECONDS]
       lindm-agent status
       lindm-agent trust-status
       lindm-agent update-status
       lindm-agent trust-update -file FILE
       lindm-agent resource-prepare -file FILE
       lindm-agent resource-start -file FILE
       lindm-agent resource-status -file FILE
       lindm-agent resource-attest -file FILE
       lindm-agent action-prepare -file FILE
       lindm-agent action-start -file FILE
       lindm-agent action-status -file FILE
       lindm-agent action-attest -file FILE
       lindm-agent action-confirm -file FILE
       lindm-agent action-credential -action UUID
       lindm-agent action-sandbox [-install]
       lindm-agent recovery-run -config FILE
       lindm-agent version
       lindm-agent help

inspect collects bounded local host evidence and a complete native package
inventory, emitting protobuf JSON to stdout. It requires no configuration.
Unavailable or failed package collection is printed with its typed status and
returns a nonzero exit code. No enrollment, service, or lifecycle claim is made.

verify-bootstrap validates bootstrap trust material without enrolling a device.
executor, bootstrap, resume, and status use /etc/lindm/executor.json.
run uses /etc/lindm/agent.json as the configured unprivileged network account.
trust-update relays signed execution trust through the root-authenticated socket
using /etc/lindm/agent.json. Only root or the configured network UID may submit it.
It never changes TLS enrollment pins or starts an operation.
trust-status reads the protected root/delegation counters, digests and historical
expiry through that socket. It does not collect native evidence or mutate trust.
resource-prepare/start/status/attest use the same socket and network configuration.
Prepare verifies signed intent and returns preflight evidence; start relays a
separately signed short-lived grant. Start acceptance is not native completion:
read resource-status for the durable result. resource-attest returns a nonce-bound
device-signed snapshot of that history, not a fresh native observation or current
compliance. These commands cannot sign execution authority.
action-* commands relay the separate imperative-action protocol. action-credential
is root-only and reads an owner unlock credential from a protected stdin pipe,
never argv or a plaintext file. Bytes are exact; do not append a newline.
recovery-run is the signed recovery image's root-only entrypoint. It cannot enroll,
serve general device/admin operations, or start without fresh online authority.
session is the unprivileged per-user remote-assistance helper (systemd user unit
lindm-session.service). It refuses root, verifies the session socket peer is root,
and uses only the caller's session bus, desktop portal and notifications.
version prints the packaging version and a newline.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "lindm-agent:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("expected a command; run lindm-agent help")
	}
	switch args[0] {
	case "verify-bootstrap":
		return verifyBootstrap(ctx, args[1:])
	case "executor":
		return serveExecutor(ctx, args[1:])
	case "inventory-observe":
		return inventoryObserveCommand(ctx, args[1:], output)
	case "run":
		return serveNetwork(ctx, args[1:])
	case "session":
		return sessionCommand(ctx, args[1:])
	case "bootstrap":
		return bootstrapCommand(ctx, args[1:])
	case "offline-export", "offline-import":
		return offlineEnrollmentCommand(ctx, args[0], args[1:])
	case "resume":
		return resumeCommand(ctx, args[1:])
	case "status":
		return statusCommand(ctx, args[1:], output)
	case "trust-status":
		return executionTrustStatusCommand(ctx, args[1:], output)
	case "trust-update":
		return executionTrustCommand(ctx, args[1:], output)
	case "resource-prepare", "resource-start", "resource-status", "resource-attest":
		return resourceExecutionCommand(ctx, args[0], args[1:], output)
	case "action-prepare", "action-start", "action-status", "action-attest", "action-confirm":
		return deviceActionCommand(ctx, args[0], args[1:], output)
	case "action-credential":
		return actionCredentialCommand(ctx, args[1:])
	case "action-sandbox":
		return actionSandboxCommand(ctx, args[1:], output)
	case "package-transaction":
		return packageTransactionCommand(ctx, args[1:])
	case "resource-transaction":
		return resourceTransactionCommand(ctx, args[1:], false)
	case "resource-observe":
		return resourceTransactionCommand(ctx, args[1:], true)
	case "firewall-restore":
		return serveFirewallRestore(ctx, args[1:])
	case "connectivity-guard":
		return serveConnectivityGuard(ctx, args[1:])
	case "connectivity-probe":
		return serveConnectivityProbe(ctx, args[1:])
	case "live-root-poweroff":
		return liveRootPoweroff(ctx, args[1:])
	case "recovery-run":
		return recoveryRun(ctx, args[1:])
	case "update-apply":
		return updateApplyCommand(ctx, args[1:])
	case "update-status":
		return updateStatusCommand(ctx, args[1:], output)
	case "version":
		return versionCommand(args[1:], output)
	case "help", "--help", "-h":
		_, err := io.WriteString(output, usage)
		return err
	case "inspect":
		if len(args) != 1 {
			return errors.New("inspect accepts no flags or paths")
		}
		return inspect(ctx, output)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func inspect(ctx context.Context, output io.Writer) error {
	observation, err := inventory.Collect(ctx)
	if err != nil {
		return err
	}
	data, err := (protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}).Marshal(observation)
	if err != nil {
		return fmt.Errorf("encode observation: %w", err)
	}
	if _, err := output.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write observation: %w", err)
	}
	if observation.Packages.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		return fmt.Errorf("package collection: %s", observation.Packages.Status)
	}
	return nil
}
