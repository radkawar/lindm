//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/localrpc"
	"lindm/internal/protodata"
)

func executionTrustCommand(ctx context.Context, args []string, output io.Writer) (err error) {
	flags := flag.NewFlagSet("trust-update", flag.ContinueOnError)
	path := flags.String("file", "", "protobuf JSON containing signed execution trust updates")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" {
		return errors.New("trust-update requires -file FILE")
	}
	data, err := readNoFollow(*path, 512<<10, false)
	if err != nil {
		return err
	}
	request := new(agentv1.UpdateExecutionTrustRequest)
	if err := protojson.Unmarshal(data, request); err != nil {
		return errors.New("invalid execution trust update JSON")
	}
	if err := protovalidate.Validate(request); err != nil {
		return errors.New("invalid execution trust update")
	}
	document, err := config.Load(config.NetworkConfigPath)
	if err != nil {
		return err
	}
	client, cleanup, err := localrpc.Dial(document.SocketPath)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	response, err := client.UpdateExecutionTrust(call, connect.NewRequest(request))
	if err != nil {
		return err
	}
	if err := protovalidate.Validate(response.Msg); err != nil {
		return errors.New("invalid execution trust receipt")
	}
	if err := protodata.ValidateClosed(response.Msg.ProtoReflect()); err != nil {
		return errors.New("unknown execution trust receipt fields")
	}
	encoded, err := (protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}).Marshal(response.Msg)
	if err != nil {
		return err
	}
	_, err = output.Write(append(encoded, '\n'))
	return err
}
