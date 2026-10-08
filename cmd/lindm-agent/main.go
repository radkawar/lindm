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
       lindm-agent bootstrap -root FILE -bundle FILE -grant FILE
       lindm-agent resume
       lindm-agent status
       lindm-agent version
       lindm-agent help

inspect collects bounded local host evidence and a complete native package
inventory, emitting protobuf JSON to stdout. It requires no configuration.
Unavailable or failed package collection is printed with its typed status and
returns a nonzero exit code. No enrollment, service, or lifecycle claim is made.

verify-bootstrap validates bootstrap trust material without enrolling a device.
executor, bootstrap, resume, and status use /etc/lindm/executor.json.
run uses /etc/lindm/agent.json as the configured unprivileged network account.
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
	case "run":
		return serveNetwork(ctx, args[1:])
	case "bootstrap":
		return bootstrapCommand(ctx, args[1:])
	case "resume":
		return resumeCommand(ctx, args[1:])
	case "status":
		return statusCommand(ctx, args[1:], output)
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
