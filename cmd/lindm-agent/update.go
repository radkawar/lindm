// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/localrpc"
	"lindm/internal/agent/update"
)

func updateApplyCommand(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("update-apply", flag.ContinueOnError)
	directory := flags.String("transaction", "", "owned protected transaction directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *directory == "" {
		return errors.New("update-apply requires -transaction DIRECTORY")
	}
	call, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	return update.Apply(call, *directory)
}

func updateStatusCommand(ctx context.Context, args []string, output io.Writer) (resultErr error) {
	if len(args) != 0 {
		return errors.New("update-status accepts no arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("update-status requires root")
	}
	doc, err := config.Load(config.ExecutorConfigPath)
	if err != nil {
		return err
	}
	client, cleanup, err := localrpc.Dial(doc.SocketPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanup()) }()
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := client.GetAgentUpdate(call, connect.NewRequest(&agentv1.GetAgentUpdateRequest{}))
	if err != nil {
		return err
	}
	data, err := protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}.Marshal(response.Msg)
	if err != nil {
		return err
	}
	_, err = output.Write(append(data, '\n'))
	return err
}
