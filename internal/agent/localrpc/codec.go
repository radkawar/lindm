// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localrpc

import (
	"errors"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// strictJSONCodec rejects unknown JSON fields. Connect's default JSON codec
// discards them, which is not acceptable for local authority messages.
type strictJSONCodec struct{ name string }

func (c strictJSONCodec) Name() string { return c.name }

func (strictJSONCodec) Marshal(message any) ([]byte, error) {
	protoMessage, ok := message.(proto.Message)
	if !ok {
		return nil, errors.New("not a protobuf message")
	}
	return protojson.MarshalOptions{}.Marshal(protoMessage)
}

func (strictJSONCodec) Unmarshal(data []byte, message any) error {
	protoMessage, ok := message.(proto.Message)
	if !ok {
		return errors.New("not a protobuf message")
	}
	return (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, protoMessage)
}
