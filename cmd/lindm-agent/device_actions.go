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

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/agent/config"
	"lindm/internal/agent/localrpc"
	"lindm/internal/protodata"
)

// deviceActionCommand only relays typed signed bytes. It cannot grant authority.
func deviceActionCommand(ctx context.Context, command string, args []string, output io.Writer) (err error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	path := flags.String("file", "", "typed device action request in protobuf JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" {
		return errors.New("device action commands require -file FILE")
	}
	data, err := readNoFollow(*path, 256<<10, false)
	if err != nil {
		return err
	}
	var request proto.Message
	switch command {
	case "action-prepare":
		request = new(agentv1.PrepareDeviceActionRequest)
	case "action-start":
		request = new(agentv1.StartDeviceActionRequest)
	case "action-status":
		request = new(agentv1.GetDeviceActionRequest)
	case "action-attest":
		request = new(agentv1.AttestDeviceActionRequest)
	case "action-confirm":
		request = new(agentv1.ConfirmDeviceActionEscrowRequest)
	default:
		return errors.New("invalid device action command")
	}
	if err := protojson.Unmarshal(data, request); err != nil {
		return errors.New("invalid device action request JSON")
	}
	if err := protovalidate.Validate(request); err != nil {
		return errors.New("invalid device action request")
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
	case *agentv1.PrepareDeviceActionRequest:
		response, callErr := client.PrepareDeviceAction(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	case *agentv1.StartDeviceActionRequest:
		response, callErr := client.StartDeviceAction(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	case *agentv1.GetDeviceActionRequest:
		response, callErr := client.GetDeviceAction(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	case *agentv1.AttestDeviceActionRequest:
		response, callErr := client.AttestDeviceAction(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	case *agentv1.ConfirmDeviceActionEscrowRequest:
		response, callErr := client.ConfirmDeviceActionEscrow(call, connect.NewRequest(request))
		if callErr != nil {
			return callErr
		}
		result = response.Msg
	}
	if err := protovalidate.Validate(result); err != nil {
		return errors.New("invalid device action response")
	}
	if err := protodata.ValidateClosed(result.ProtoReflect()); err != nil {
		return errors.New("unknown device action response fields")
	}
	encoded, err := (protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}).Marshal(result)
	if err != nil {
		return err
	}
	_, err = output.Write(append(encoded, '\n'))
	return err
}

// actionCredentialCommand reads exactly the bytes on stdin. It refuses a terminal
// to prevent an echoed passphrase; callers use a protected pipe, never argv/files.
func actionCredentialCommand(ctx context.Context, args []string) (err error) {
	if os.Geteuid() != 0 {
		return errors.New("action-credential requires root")
	}
	flags := flag.NewFlagSet("action-credential", flag.ContinueOnError)
	action := flags.String("action", "", "prepared action UUID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *action == "" {
		return errors.New("action-credential requires -action UUID and a protected stdin pipe")
	}
	info, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&(os.ModeNamedPipe|os.ModeSocket) == 0 {
		return errors.New("credential input must be a protected pipe, not a terminal or plaintext file")
	}
	if err := actionprovider.PinLiveRootMemory(); err != nil {
		return err
	}
	credential, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	defer clear(credential)
	if err != nil {
		return errors.New("read owner credential failed")
	}
	request := &agentv1.SupplyDeviceActionCredentialRequest{ActionId: *action, Credential: credential}
	if err := protovalidate.Validate(request); err != nil {
		return errors.New("invalid action UUID or owner credential size")
	}
	document, err := config.Load(config.ExecutorConfigPath)
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
	_, err = client.SupplyDeviceActionCredential(call, connect.NewRequest(request))
	return err
}
