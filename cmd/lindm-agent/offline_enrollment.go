// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/localrpc"
)

func offlineEnrollmentCommand(ctx context.Context, command string, args []string) (err error) {
	if os.Geteuid() != 0 {
		return errors.New("offline enrollment requires root")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	file := flags.String("file", "", "signed authorization or response protobuf JSON file")
	out := flags.String("out", "", "new root-only request output file")
	root := flags.String("root", "", "authenticated execution-root document")
	bundle := flags.String("bundle", "", "DSSE-signed bootstrap bundle")
	resume := flags.Bool("resume", false, "export the existing protected request without creating an identity")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected offline enrollment arguments")
	}
	if command == "offline-export" {
		if *out == "" || (!*resume && (*file == "" || *root == "" || *bundle == "")) || (*resume && (*file != "" || *root != "" || *bundle != "")) {
			return errors.New("offline-export requires -root FILE -bundle FILE -file AUTHORIZATION -out REQUEST, or -resume -out REQUEST")
		}
	} else if *file == "" || *out != "" || *root != "" || *bundle != "" || *resume {
		return errors.New("offline-import requires -file RESPONSE")
	}
	doc, err := config.Load(config.ExecutorConfigPath)
	if err != nil {
		return err
	}
	client, cleanup, err := localrpc.Dial(doc.SocketPath)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	if command == "offline-export" {
		request := &agentv1.PrepareBootstrapRequest{Resume: *resume}
		if !*resume {
			request.ExecutionRootJson, err = readNoFollow(*root, 64<<10, false)
			if err != nil {
				return err
			}
			request.BootstrapEnvelope, err = readNoFollow(*bundle, 512<<10, false)
			if err != nil {
				return err
			}
			request.OfflineAuthorization = new(agentv1.OfflineEnrollmentAuthorizationFile)
			if err := readOfflineDocument(*file, request.OfflineAuthorization); err != nil {
				return err
			}
		}
		response, err := client.PrepareBootstrap(ctx, connect.NewRequest(request))
		if err != nil {
			return err
		}
		if response.Msg.GetOfflineRequest() == nil {
			return errors.New("protected pending transaction is not an offline enrollment")
		}
		if err := writeOfflineDocument(*out, response.Msg.GetOfflineRequest()); err != nil {
			return err
		}
		_, err = fmt.Println("Signed offline enrollment request exported; transfer it to an authorized deployment administrator.")
		return err
	}
	response := new(agentv1.OfflineEnrollmentResponseFile)
	if err := readOfflineDocument(*file, response); err != nil {
		return err
	}
	installed, err := client.ImportOfflineEnrollment(ctx, connect.NewRequest(&agentv1.ImportOfflineEnrollmentRequest{Response: response}))
	if err != nil {
		return err
	}
	_, err = fmt.Printf("Installed offline enrollment for device %s generation %s.\n", installed.Msg.GetEnrollment().GetDeviceId(), installed.Msg.GetEnrollment().GetEnrollmentGeneration())
	return err
}

func readOfflineDocument(path string, message proto.Message) error {
	data, err := readNoFollow(path, 768<<10, true)
	if err != nil {
		return err
	}
	if err := protojson.Unmarshal(data, message); err != nil {
		return errors.New("invalid offline enrollment document")
	}
	return nil
}

// Exclusive creation never follows/replaces an existing destination. A power
// loss can leave a partial export, but never a different protected transaction;
// -resume exports the same signed request to a new file.
func writeOfflineDocument(path string, message proto.Message) (err error) {
	data, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(message)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()
	return directory.Sync()
}
