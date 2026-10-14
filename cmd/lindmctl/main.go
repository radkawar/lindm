// SPDX-License-Identifier: Apache-2.0

// Command lindmctl manages a lindm server through browser-authorized CLI sessions.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"lindm/internal/agent/buildinfo"
	"lindm/internal/ctl"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		if _, err := fmt.Fprint(os.Stdout, buildinfo.Line()); err != nil {
			os.Exit(1)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := ctl.Run(ctx, os.Args[1:], os.Stdout, ctl.OpenBrowser); err != nil {
		if _, writeErr := fmt.Fprintln(os.Stderr, "lindmctl:", err); writeErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}
