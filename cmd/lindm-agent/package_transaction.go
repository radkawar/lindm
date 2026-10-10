//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"os"

	"lindm/internal/agent/config"
	"lindm/internal/agent/nativehelper"
)

func packageTransactionCommand(ctx context.Context, args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("package transaction helper requires root")
	}
	flags := flag.NewFlagSet("package-transaction", flag.ContinueOnError)
	transactionID := flags.String("transaction", "", "protected native transaction UUID")
	phase := flags.String("phase", "", "protected request phase, prepare or apply")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *transactionID == "" || (*phase != "prepare" && *phase != "apply") {
		return errors.New("package transaction helper requires -transaction UUID and -phase prepare|apply")
	}
	document, err := config.Load(config.ExecutorConfigPath)
	if err != nil {
		return err
	}
	return nativehelper.Run(ctx, document, *transactionID, *phase)
}
