// SPDX-License-Identifier: Apache-2.0

package core

import (
	"errors"
	"strconv"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/types/dynamicpb"

	adminv1 "lindm/gen/lindm/admin/v1"
)

// The validator is compiled eagerly for validatedMessages only, so an admin RPC
// whose request type is missing there is refused as invalid before its handler
// runs. Every AdminService request must validate.
func TestEveryAdminRequestIsValidated(t *testing.T) {
	validator, err := deviceRules()
	if err != nil {
		t.Fatal(err)
	}
	methods := adminv1.File_lindm_admin_v1_admin_proto.Services().ByName("AdminService").Methods()
	for i := range methods.Len() {
		method := methods.Get(i)
		request := dynamicpb.NewMessage(method.Input())
		if err := validator.Validate(request); err != nil {
			if _, compile := err.(*protovalidate.CompilationError); compile {
				t.Errorf("%s: request %s is not registered for validation", method.Name(), method.Input().FullName())
			}
		}
	}
}

// Sharing compiled rules must not share a request's violations or weaken the
// fail-closed behavior when multiple independent services validate concurrently.
func TestDeviceRulesConcurrentValidation(t *testing.T) {
	for i := range 16 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			rules, err := deviceRules()
			if err != nil {
				t.Fatal(err)
			}
			for range 8 {
				err := rules.Validate(&adminv1.GetDeviceRequest{DeviceId: "not-a-uuid"})
				var violation *protovalidate.ValidationError
				if !errors.As(err, &violation) {
					t.Fatalf("invalid request did not produce a validation error: %v", err)
				}
				if err := rules.Validate(&adminv1.GetDeviceRequest{DeviceId: "a48d2bb9-a420-473c-84e0-08f098e04ff3"}); err != nil {
					t.Fatalf("valid request inherited another request's error: %v", err)
				}
			}
		})
	}
}
