//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"os"

	"lindm/internal/agent/capabilitypolicy"
	"lindm/internal/agent/nativehelper"
)

func resourceTransactionCommand(ctx context.Context, args []string, observe bool) error {
	if os.Geteuid() != 0 {
		return errors.New("native resource helper requires root")
	}
	name, argument := "resource-transaction", "transaction"
	if observe {
		name, argument = "resource-observe", "observation"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	identity := flags.String(argument, "", "protected native operation UUID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *identity == "" {
		return errors.New("native helper requires exactly one operation UUID")
	}
	effective, err := capabilitypolicy.LoadEffectiveExecutorConfig(ctx)
	if err != nil {
		return err
	}
	if observe {
		return nativehelper.RunObservation(ctx, effective.Document, *identity)
	}
	return nativehelper.RunResource(ctx, effective.Document, *identity)
}
