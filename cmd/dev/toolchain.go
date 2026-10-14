// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"lindm/internal/devlab/toolchain"
)

// runToolchainPath prints the PATH make recipes run with: the pinned Node and
// Go first, so `node --test`, npm and the lab binaries never pick up whatever
// the caller's shell puts first.
func runToolchainPath(args []string) error {
	if len(args) != 0 {
		return errors.New("toolchain-path takes no arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	root, err := toolchain.ModuleRoot(".")
	if err != nil {
		return err
	}
	environ, err := toolchain.Environ(ctx, root, os.Environ())
	if err != nil {
		return err
	}
	for _, entry := range environ {
		if path, ok := strings.CutPrefix(entry, "PATH="); ok {
			_, err := fmt.Println(path)
			return err
		}
	}
	return errors.New("toolchain-path: no PATH")
}
