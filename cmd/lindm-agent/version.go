// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"io"

	"lindm/internal/agent/buildinfo"
)

func versionCommand(args []string, output io.Writer) error {
	if len(args) != 0 {
		return errors.New("version accepts no arguments")
	}
	_, err := io.WriteString(output, buildinfo.Line())
	return err
}
