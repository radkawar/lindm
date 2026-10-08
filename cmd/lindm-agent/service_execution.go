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
func serviceExecutionCommand(ctx context.Context, command string, args []string, output io.Writer) (err error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	path := flags.String("file", "", "typed service execution request in protobuf JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" {
		return errors.New("service execution commands require -file FILE")
	}
	data, err := readNoFollow(*path, 64<<10, false)
	if err != nil {
		return err
	}
	var request proto.Message
	switch command {
	case "service-prepare":
		request = new(agentv1.PrepareServiceExecutionRequest)
	case "service-start":
		request = new(agentv1.StartServiceExecutionRequest)
	case "service-status":
		request = new(agentv1.GetServiceExecutionRequest)
	case "service-attest":
		request = new(agentv1.AttestServiceExecutionRequest)
	default:
		return errors.New("invalid service execution command")
	}
	if err := protojson.Unmarshal(data, request); err != nil {
		return errors.New("invalid service execution request JSON")
	}
	if err := protovalidate.Validate(request); err != nil {
		return errors.New("invalid service execution request")
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
	case *agentv1.PrepareServiceExecutionRequest:
		response, callErr := client.PrepareServiceExecution(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	case *agentv1.StartServiceExecutionRequest:
		response, callErr := client.StartServiceExecution(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	case *agentv1.GetServiceExecutionRequest:
		response, callErr := client.GetServiceExecution(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	case *agentv1.AttestServiceExecutionRequest:
		response, callErr := client.AttestServiceExecution(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	}
	if err := protovalidate.Validate(result); err != nil {
		return errors.New("invalid service execution response")
	}
	if err := protodata.ValidateClosed(result.ProtoReflect()); err != nil {
		return errors.New("unknown service execution response fields")
	}
	encoded, err := (protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}).Marshal(result)
	if err != nil {
		return err
	}
	_, err = output.Write(append(encoded, '\n'))
	return err
}
