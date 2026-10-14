// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"lindm/internal/devlab"
)

func runAuthCheckBroker(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("auth check-broker", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("repo", ".", "checkout owning the protected maintained development fixture")
	binary := flags.String("lindmd", "", "prebuilt lindmd executable; never builds or resets the shared fixture")
	cleanup := flags.String("cleanup-prefix", "", "remove only this complete lindm-broker-check-UUID prefix from the two dedicated fixture realms")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*binary == "") == (*cleanup == "") {
		return errors.New("auth check-broker requires exactly one of -lindmd FILE or -cleanup-prefix lindm-broker-check-UUID; optional -repo DIR")
	}
	return devlab.CheckBrokerAuthorization(ctx, *root, *binary, *cleanup, stdout)
}
