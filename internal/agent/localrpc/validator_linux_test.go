// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localrpc

import (
	"errors"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoregistry"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Lazy compilation is off, so every executor request must be compiled up
// front; a missing one (ImportOfflineEnrollmentRequest was) fails every call
// before its handler runs.
func TestExecutorValidatorCompilesEveryRequest(t *testing.T) {
	validator, err := executorValidator()
	if err != nil {
		t.Fatal(err)
	}
	methods := agentv1.File_lindm_agent_v1_executor_proto.Services().ByName("ExecutorService").Methods()
	for i := range methods.Len() {
		input := methods.Get(i).Input()
		kind, err := protoregistry.GlobalTypes.FindMessageByName(input.FullName())
		if err != nil {
			t.Fatal(err)
		}
		var compilation *protovalidate.CompilationError
		if err := validator.Validate(kind.New().Interface()); errors.As(err, &compilation) {
			t.Errorf("%s: %v", input.FullName(), err)
		}
	}
}
