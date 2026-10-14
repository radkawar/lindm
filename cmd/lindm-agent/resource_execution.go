// SPDX-License-Identifier: Apache-2.0

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
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/localrpc"
	"lindm/internal/protodata"
)

// These commands relay typed signed authority; they cannot construct native
// plans, select keys or authorize operations on behalf of the signer.
func resourceExecutionCommand(ctx context.Context, command string, args []string, output io.Writer) (err error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	path := flags.String("file", "", "typed resource execution request in protobuf JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" {
		return errors.New("resource execution commands require -file FILE")
	}
	data, err := readNoFollow(*path, 1<<20, false)
	if err != nil {
		return err
	}
	var request proto.Message
	switch command {
	case "resource-prepare":
		request = new(agentv1.PrepareResourceExecutionRequest)
	case "resource-start":
		request = new(agentv1.StartResourceExecutionRequest)
	case "resource-status":
		request = new(agentv1.GetResourceExecutionRequest)
	case "resource-attest":
		request = new(agentv1.AttestResourceExecutionRequest)
	default:
		return errors.New("invalid resource execution command")
	}
	if err := protojson.Unmarshal(data, request); err != nil {
		return errors.New("invalid resource execution request JSON")
	}
	if err := protovalidate.Validate(request); err != nil {
		return errors.New("invalid resource execution request")
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
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var result proto.Message
	switch request := request.(type) {
	case *agentv1.PrepareResourceExecutionRequest:
		response, callErr := client.PrepareResourceExecution(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	case *agentv1.StartResourceExecutionRequest:
		response, callErr := client.StartResourceExecution(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	case *agentv1.GetResourceExecutionRequest:
		response, callErr := client.GetResourceExecution(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	case *agentv1.AttestResourceExecutionRequest:
		response, callErr := client.AttestResourceExecution(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	}
	if err := protovalidate.Validate(result); err != nil {
		return errors.New("invalid resource execution response")
	}
	if err := protodata.ValidateClosed(result.ProtoReflect()); err != nil {
		return errors.New("unknown resource execution response fields")
	}
	encoded, err := (protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}).Marshal(result)
	if err != nil {
		return err
	}
	_, err = output.Write(append(encoded, '\n'))
	return err
}
