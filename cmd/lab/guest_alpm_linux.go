//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"lindm/internal/agent/inventory"
	"lindm/internal/agent/packageprovider"
)

func guestALPMLock(ctx context.Context, archive string, output io.Writer) error {
	product, err := inventory.HostPlatform(ctx)
	if err != nil {
		return err
	}
	data, err := packageprovider.ProbeALPMNativeLock(ctx, product, filepath.Dir(filepath.Dir(archive)), archive)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, string(data))
	return err
}
