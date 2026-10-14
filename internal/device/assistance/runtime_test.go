// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/core"
)

func TestAssistanceRequiresCoreAndRuntime(t *testing.T) {
	if service, err := New(nil, NewRuntime()); err == nil || service != nil {
		t.Fatal("missing core admitted")
	}
	if service, err := New(&core.Service{}, nil); err == nil || service != nil {
		t.Fatal("missing runtime admitted")
	}
}

func TestAssistanceRuntimeSharedLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		newService := func(runtime *Runtime) *Service {
			t.Helper()
			service, err := New(&core.Service{Clock: time.Now}, runtime)
			if err != nil {
				t.Fatal(err)
			}
			return service
		}
		runtime := NewRuntime()
		admin, device := newService(runtime), newService(runtime)
		isolated := newService(NewRuntime())
		id := uuid.New()
		remember := func(service *Service, lifetime time.Duration) *assistanceCommandMemory {
			t.Helper()
			command := &agentv1.AssistanceCommand{
				RequestId: uuid.NewString(), Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE,
				Text: "ephemeral", Deadline: timestamppb.New(service.Now().Add(lifetime)),
			}
			return service.runtime.rememberAssistanceCommand(id, command, service.Now())
		}
		assertSlot := func(service *Service, want *assistanceCommandMemory) {
			t.Helper()
			service.runtime.assistanceMu.Lock()
			defer service.runtime.assistanceMu.Unlock()
			if got := service.runtime.assistanceCommands[id]; got != want {
				t.Fatal("runtime slot visibility differs")
			}
			if len(service.runtime.assistanceCommands) > 1 {
				t.Fatal("one session retained multiple command slots")
			}
		}

		old := remember(admin, time.Second)
		assertSlot(device, old)
		assertSlot(isolated, nil)
		private := remember(isolated, time.Minute)
		replacement := remember(device, 2*time.Second)
		admin.runtime.forgetAssistanceCommand(id, old)
		assertSlot(admin, replacement)
		// Virtual time deterministically runs destruction without another RPC.
		time.Sleep(time.Second)
		synctest.Wait()
		assertSlot(admin, replacement)
		time.Sleep(time.Second)
		synctest.Wait()
		assertSlot(admin, nil)
		assertSlot(device, nil)
		assertSlot(isolated, private)

		forgotten := remember(admin, time.Minute)
		device.runtime.forgetAssistanceCommand(id, forgotten)
		assertSlot(admin, nil)
		remember(admin, time.Minute)
		device.revokeAssistance(assistanceRevocations{{ID: id}})
		assertSlot(admin, nil)
		assertSlot(isolated, private)
		isolated.runtime.forgetAssistanceCommand(id, private)
	})
}
