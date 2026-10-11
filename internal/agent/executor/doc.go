// Package executor is the agent's root-owned authority boundary. Service
// implements the local ExecutorService. The unprivileged network agent reaches
// it only through localrpc. It holds the device identity and TLS keys and the
// execution-trust view. It owns every privileged effect: signed resource
// executions (prepare, executor challenge, signed start grant, worker,
// attestation, read-only observation), signed device actions (lock, power,
// local-admin and recovery-key escrow, wipe, recovery boot, live-root erase,
// agent update), inventory refresh, root inventory, offline enrollment and the
// assistance broker for desktop sessions. Each effect requires a server intent
// signed under the delegated trust roots. The action is journaled before any
// native call and fenced by boot ID, deadlines and replay checks.
//
// Non-goals: executor never talks to the server directly; transport relays
// for it. The OS-specific work lives in native providers and helpers that
// executor calls only after its own gate. Private keys never leave its
// methods.
package executor
