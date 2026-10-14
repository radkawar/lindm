// SPDX-License-Identifier: Apache-2.0

// Package protodata checks bounded, closed protobuf payloads used for authority
// and protected state. These finite schemas intentionally contain no maps.
package protodata

import (
	"errors"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// ValidateClosed rejects unrecognized fields, including nested messages. Maps
// require a separately reviewed canonical encoding and are not admitted here.
func ValidateClosed(message protoreflect.Message) error {
	if len(message.GetUnknown()) != 0 {
		return errors.New("unrecognized protobuf field")
	}
	var err error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsMap() {
			err = errors.New("map fields are not admitted in closed protobuf payloads")
			return false
		}
		if field.Message() == nil {
			return true
		}
		if field.IsList() {
			list := value.List()
			for i := range list.Len() {
				if err = ValidateClosed(list.Get(i).Message()); err != nil {
					return false
				}
			}
		} else {
			err = ValidateClosed(value.Message())
		}
		return err == nil
	})
	return err
}
