// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/inventory"
	"lindm/internal/protodata"
)

const maxRootObservationJSON = 80 * 1024

type inventoryObservationSources struct {
	euid    func() int
	bootID  func() (string, error)
	collect func(context.Context, string) *inventoryv1.RootObservation
}

// inventoryObserveCommand is the fixed, configuration-free entrypoint used by
// the short-lived read-only observation unit. It never loads executor identity.
func inventoryObserveCommand(ctx context.Context, args []string, output io.Writer) error {
	return inventoryObserve(ctx, args, output, inventoryObservationSources{
		euid: os.Geteuid, bootID: readInventoryBootID,
		collect: inventory.CollectRootObservation,
	})
}

func readInventoryBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	text := strings.TrimRight(string(data), "\n")
	id, err := uuid.Parse(text)
	if err != nil || id.String() != text {
		return "", errors.New("invalid boot id")
	}
	return text, nil
}

func inventoryObserve(ctx context.Context, args []string, output io.Writer, sources inventoryObservationSources) error {
	if len(args) != 0 {
		return errors.New("inventory-observe accepts no flags or paths")
	}
	if sources.euid() != 0 {
		return errors.New("inventory-observe requires root")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	boot, err := sources.bootID()
	if err != nil {
		return fmt.Errorf("read observation boot id: %w", err)
	}
	observation := sources.collect(ctx, boot)
	if err := ctx.Err(); err != nil {
		return err
	}
	if observation == nil {
		return errors.New("missing root observation")
	}
	if err := protodata.ValidateClosed(observation.ProtoReflect()); err != nil {
		return fmt.Errorf("validate root observation: %w", err)
	}
	if err := protovalidate.Validate(observation); err != nil {
		return fmt.Errorf("validate root observation: %w", err)
	}
	if observation.GetBootId() != boot {
		return errors.New("root observation boot id mismatch")
	}
	data, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(observation)
	if err != nil {
		return fmt.Errorf("encode root observation: %w", err)
	}
	if len(data)+1 > maxRootObservationJSON {
		return errors.New("root observation exceeds output limit")
	}
	currentBoot, err := sources.bootID()
	if err != nil {
		return fmt.Errorf("recheck observation boot id: %w", err)
	}
	if currentBoot != boot {
		return errors.New("boot changed during root observation")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data = append(data, '\n')
	n, err := output.Write(data)
	if err != nil {
		return fmt.Errorf("write root observation: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("write root observation: %w", io.ErrShortWrite)
	}
	return nil
}
