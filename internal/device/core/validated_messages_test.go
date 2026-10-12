package core

import (
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/types/dynamicpb"

	adminv1 "lindm/gen/lindm/admin/v1"
)

// The validator is compiled eagerly for validatedMessages only, so an admin RPC
// whose request type is missing there is refused as invalid before its handler
// runs. Every AdminService request must validate.
func TestEveryAdminRequestIsValidated(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(validatedMessages()...), protovalidate.WithDisableLazy())
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
