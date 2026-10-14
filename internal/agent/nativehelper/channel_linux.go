// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nativehelper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/protodata"
)

// Private after-images can include bounded file bytes and security metadata.
const channelLimit = recordLimit

func requireRootPeer(connection *net.UnixConn) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var credential *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		credential, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}
	if credential == nil || credential.Uid != 0 {
		return errors.New("package_helper_peer_not_root")
	}
	return nil
}

func sendMessage(connection io.Writer, message *agentv1.NativeHelperMessage) error {
	encoded, err := encodeRecord(message)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if len(encoded) > channelLimit {
		return errors.New("package_helper_channel_capacity")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(encoded)))
	if _, err := io.Copy(connection, bytes.NewReader(header[:])); err != nil {
		return err
	}
	_, err = io.Copy(connection, bytes.NewReader(encoded))
	return err
}

func receiveMessage(connection io.Reader) (*agentv1.NativeHelperMessage, error) {
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > channelLimit {
		return nil, errors.New("package_helper_channel_capacity")
	}
	encoded := make([]byte, int(length))
	defer clear(encoded)
	if _, err := io.ReadFull(connection, encoded); err != nil {
		return nil, err
	}
	message := new(agentv1.NativeHelperMessage)
	if err := proto.Unmarshal(encoded, message); err != nil {
		return nil, err
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(message); err != nil {
		return nil, err
	}
	return message, nil
}
