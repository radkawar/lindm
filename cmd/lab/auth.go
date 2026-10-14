// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/devlab"
)

func runAuthCheck(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	flags := flag.NewFlagSet("auth check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("repo", ".", "checkout owning the protected development fixture")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("auth check accepts only -repo DIR")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	session, err := devlab.OpenOwnerSession(ctx, *root)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, session.Close(cleanup))
	}()
	response, err := session.Admin.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 1}))
	if err != nil {
		return fmt.Errorf("authorized fixture admin read failed: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "real owner authorization-code/S256-PKCE login and authenticated admin read accepted (%d devices in bounded page); revoking session on exit\n", len(response.Msg.GetDevices()))
	return err
}

func runAuthCheckFresh(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("auth check-fresh", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("repo", ".", "checkout owning the protected development fixture")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("auth check-fresh accepts only -repo DIR")
	}
	return devlab.CheckFreshAuthorization(ctx, *root, stdout)
}
