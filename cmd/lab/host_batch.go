//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"

	"lindm/internal/labhost"
)

type hostBatchCredentialKey struct{}

func runHostBatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) != 2 {
		return errors.New("invalid internal host-batch invocation")
	}
	config, err := labhost.LoadFile(args[0])
	if err != nil {
		return err
	}
	if len(config.GetHosts()) != 1 {
		return errors.New("host-batch requires exactly one host")
	}
	guests, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return err
	}
	slots, err := labhost.OpenSlots(config.Hosts[0])
	if err != nil {
		return err
	}
	return withHostLifetime(ctx, func(ctx context.Context) error {
		err := slots.ServeBatch(ctx, uint32(guests), laneTiming(true).Admission, laneWaitReporter(stderr, config.Hosts[0].GetName()), func(credential string) error {
			_, err := fmt.Fprintln(stdout, credential)
			return err
		})
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return nil
		}
		return err
	})
}

func runHostBatchExec(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("invalid internal host-exec-batch invocation")
	}
	credential, err := labhost.ReadBatchCredential(args[0])
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, hostBatchCredentialKey{}, credential)
	return runHostExec(ctx, args[1:], stdout, stderr)
}

func withHostLifetime(ctx context.Context, run func(context.Context) error) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Reopen as a pollable descriptor so Close interrupts the lifetime reader.
	lifetime, err := os.OpenFile("/proc/self/fd/0", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(io.Discard, lifetime); cancel() }()
	defer func() { err = errors.Join(err, lifetime.Close()); <-done }()
	return run(ctx)
}
