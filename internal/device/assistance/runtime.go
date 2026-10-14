// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"sync"
	"time"

	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Runtime owns process-local assistance content independently of SQL services.
// Share one runtime between the admin admission and device sync services. It
// contains no SQL core, pool or authorization state and must not be copied.
type Runtime struct {
	assistanceMu       sync.Mutex
	assistanceCommands map[uuid.UUID]*assistanceCommandMemory
}

// NewRuntime returns an isolated assistance runtime for the composition root.
func NewRuntime() *Runtime {
	return &Runtime{}
}

// One slot per live session, never journaled. The timer destroys content even
// when clients disconnect and no subsequent RPC arrives to enforce deadlines.
type assistanceCommandMemory struct {
	command *agentv1.AssistanceCommand
	result  *agentv1.AssistanceCommandResult
	timer   *time.Timer
}

func (r *Runtime) rememberAssistanceCommand(sessionID uuid.UUID, command *agentv1.AssistanceCommand, now time.Time) *assistanceCommandMemory {
	// command is the handler's detached, server-stamped copy.
	memory := &assistanceCommandMemory{command: command}
	r.assistanceMu.Lock()
	defer r.assistanceMu.Unlock()
	if old := r.assistanceCommands[sessionID]; old != nil {
		old.timer.Stop()
	}
	if r.assistanceCommands == nil {
		r.assistanceCommands = make(map[uuid.UUID]*assistanceCommandMemory)
	}
	r.assistanceCommands[sessionID] = memory
	memory.timer = time.AfterFunc(command.GetDeadline().AsTime().Sub(now), func() { r.forgetAssistanceCommand(sessionID, memory) })
	return memory
}

func (r *Runtime) forgetAssistanceCommand(sessionID uuid.UUID, memory *assistanceCommandMemory) {
	if memory == nil {
		return
	}
	r.assistanceMu.Lock()
	defer r.assistanceMu.Unlock()
	if r.assistanceCommands[sessionID] == memory {
		memory.timer.Stop()
		delete(r.assistanceCommands, sessionID)
	}
}
