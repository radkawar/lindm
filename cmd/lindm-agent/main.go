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
       lindm-agent help

inspect collects bounded local host evidence and a complete native package
inventory, emitting protobuf JSON to stdout. It requires no configuration.
Unavailable or failed package collection is printed with its typed status and
returns a nonzero exit code. No enrollment, service, or lifecycle claim is made.

verify-bootstrap validates bootstrap trust material without enrolling a device.
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
	if len(args) > 0 && args[0] == "verify-bootstrap" {
		return verifyBootstrap(ctx, args[1:])
	}
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") ||
		len(args) == 2 && args[0] == "inspect" && (args[1] == "--help" || args[1] == "-h") {
		_, err := io.WriteString(output, usage)
		return err
	}
	if len(args) != 1 || args[0] != "inspect" {
		return errors.New("expected inspect, verify-bootstrap, or help; inspect accepts no flags or paths")
	}
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
