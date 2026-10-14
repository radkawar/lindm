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
	"lindm/internal/agent/inventory"
	"lindm/internal/agent/localrpc"
	"lindm/internal/platform"
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
	overlay, err := desktop.NewShellOverlay(bus, os.Getenv("XDG_CURRENT_DESKTOP"))
	if err != nil {
		return err
	}
	enrollments, err := desktop.NewFileEnrollmentStore()
	if err != nil {
		return err
	}
	// A helper without a usable runtime directory shares no sound; that is a
	// per-capability refusal, not a helper failure.
	var audio desktop.AudioDevices
	audioUnavailable := sessionCapabilityUnavailableReason(ctx, platform.AssistanceAudio, "platform_audio_unqualified")
	if devices, err := desktop.NewPipeWireAudio(logger); err == nil {
		audio = devices
	} else if audioUnavailable == "" {
		logger.Warn("session helper audio unavailable", "err", err)
		audioUnavailable = "pipewire_runtime_unavailable"
	}
	helper, err := desktop.New(desktop.Config{
		Client:                      client,
		Notifier:                    notifier,
		Portal:                      portal,
		Capturer:                    capturer,
		Peers:                       desktop.NewPionPeers(),
		Locks:                       desktop.LogindLockMonitor{},
		CurrentDesktop:              os.Getenv("XDG_CURRENT_DESKTOP"),
		Logger:                      logger,
		FilesUnavailableReason:      sessionCapabilityUnavailableReason(ctx, platform.AssistanceFiles, "platform_files_unqualified"),
		RecordingUnavailableReason:  sessionCapabilityUnavailableReason(ctx, platform.AssistanceRecording, "platform_recording_unqualified"),
		ReconnectUnavailableReason:  sessionCapabilityUnavailableReason(ctx, platform.AssistanceReconnect, "platform_reconnect_unqualified"),
		Overlay:                     overlay,
		Audio:                       audio,
		Enrollments:                 enrollments,
		UnattendedUnavailableReason: sessionCapabilityUnavailableReason(ctx, platform.AssistanceUnattended, "platform_unattended_unqualified"),
		ElevationUnavailableReason:  sessionCapabilityUnavailableReason(ctx, platform.AssistanceElevation, "platform_elevation_unqualified"),
		AnnotationUnavailableReason: sessionCapabilityUnavailableReason(ctx, platform.AssistanceAnnotation, "platform_annotation_unqualified"),
		AudioUnavailableReason:      audioUnavailable,
	})
	if err != nil {
		return err
	}
	logger.Info("session helper started", "socket", *socket, "uid", os.Getuid(), "current_desktop", os.Getenv("XDG_CURRENT_DESKTOP"))
	return helper.Run(ctx)
}

func sessionCapabilityUnavailableReason(ctx context.Context, capability platform.Capability, gated string) string {
	release, err := inventory.HostOSRelease(ctx)
	if err != nil {
		return "platform_identity_unavailable"
	}
	if platform.Identify(release).Gate(capability) != nil {
		return gated
	}
	return ""
}
