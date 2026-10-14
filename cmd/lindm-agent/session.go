// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"lindm/internal/agent/desktop"
	"lindm/internal/agent/localrpc"
)

// sessionCommand runs the unprivileged per-user remote-assistance helper,
// normally from the lindm-session.service systemd user unit. It talks only
// to a root-owned session socket and the user's own session bus.
func sessionCommand(ctx context.Context, args []string) (err error) {
	flags := flag.NewFlagSet("session", flag.ContinueOnError)
	socket := flags.String("socket", localrpc.DefaultSessionSocketPath, "executor session socket")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("session accepts only -socket")
	}
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return errors.New("session helper refuses to run as root")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	client, closeClient, err := localrpc.DialSession(*socket)
	if err != nil {
		return fmt.Errorf("dial session socket: %w", err)
	}
	defer func() { err = errors.Join(err, closeClient()) }()
	bus, err := desktop.ConnectSessionBus(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, bus.Close()) }()
	notifier, err := desktop.NewDesktopNotifier(bus)
	if err != nil {
		return err
	}
	portal, err := desktop.NewDesktopPortal(bus, logger)
	if err != nil {
		return err
	}
	capturer, err := desktop.NewGStreamer(logger)
	if err != nil {
		return err
	}
	helper, err := desktop.New(desktop.Config{
		Client:         client,
		Notifier:       notifier,
		Portal:         portal,
		Capturer:       capturer,
		Peers:          desktop.NewPionPeers(),
		Locks:          desktop.LogindLockMonitor{},
		CurrentDesktop: os.Getenv("XDG_CURRENT_DESKTOP"),
		Logger:         logger,
	})
	if err != nil {
		return err
	}
	logger.Info("session helper started", "socket", *socket, "uid", os.Getuid(), "current_desktop", os.Getenv("XDG_CURRENT_DESKTOP"))
	return helper.Run(ctx)
}
