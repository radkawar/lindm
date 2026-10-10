//go:build linux

package nativehelper

import (
	"errors"
	"path/filepath"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/privatecustody"
	"lindm/internal/protodata"
)

func helperCustody(directory string) (*privatecustody.Custody, error) {
	// Every helper directory is exactly <protected-state>/<fixed-category>/<UUID>.
	switch filepath.Base(filepath.Dir(directory)) {
	case "packageprovider", "resource-transactions", "resource-observations":
	default:
		return nil, errors.New("native_helper_custody_scope")
	}
	return privatecustody.OpenLocal(filepath.Dir(filepath.Dir(directory)))
}

func recordBinding(directory, name string) []byte {
	return privatecustody.Binding("native-helper-record.v1", filepath.Base(filepath.Dir(directory)), filepath.Base(directory), name)
}

func writeProtected(directory, name string, plaintext []byte) error {
	if len(plaintext) == 0 || len(plaintext) > recordLimit {
		return errors.New("native_helper_record_capacity")
	}
	custody, err := helperCustody(directory)
	if err != nil {
		return err
	}
	defer custody.Close()
	envelope, err := custody.Seal(plaintext, recordBinding(directory, name))
	if err != nil {
		return err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		return err
	}
	return writeExclusive(directory, name, encoded)
}

func readProtected(directory, name string) ([]byte, error) {
	encoded, err := readRecordBytes(directory, name)
	if err != nil {
		return nil, err
	}
	envelope := new(agentv1.PrivateCustodyEnvelope)
	if err := proto.Unmarshal(encoded, envelope); err != nil {
		return nil, err
	}
	if err := protodata.ValidateClosed(envelope.ProtoReflect()); err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(envelope); err != nil {
		return nil, err
	}
	custody, err := helperCustody(directory)
	if err != nil {
		return nil, err
	}
	defer custody.Close()
	plaintext, err := custody.Open(envelope, recordBinding(directory, name))
	if err != nil {
		return nil, err
	}
	if len(plaintext) == 0 || len(plaintext) > recordLimit {
		clear(plaintext)
		return nil, errors.New("native_helper_record_capacity")
	}
	return plaintext, nil
}
