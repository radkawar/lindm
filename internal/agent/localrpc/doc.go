// SPDX-License-Identifier: Apache-2.0

// Package localrpc is the agent's local Connect transport over Unix sockets.
// It serves and dials two separate sockets. The root executor socket carries
// ExecutorService for the unprivileged network agent; Serve admits only the
// configured network UID/GID and Dial refuses any server peer that is not
// UID 0. The session-helper socket carries SessionService for desktop session
// helpers. It admits any local UID except root and the network account and
// shares no slots or limits with the executor socket. Both sides check
// SO_PEERCRED before any HTTP exchange, bound message size and in-flight
// requests, and report denials with an rpcreason. NewTLSSigner lets the
// network agent sign TLS handshakes with a key that never leaves the executor.
//
// Non-goals: localrpc does not decide what an authenticated caller may do. The
// executor and session handlers own authorization, logind session binding and
// all state. It never speaks to the network or the server.
package localrpc
