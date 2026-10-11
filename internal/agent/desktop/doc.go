// Package desktop is the unprivileged per-user remote-assistance session
// helper started as `lindm-agent session` from a systemd user unit.
//
// The helper polls the root executor's SessionService over the session socket
// (2 s idle, 1 s while it holds sessions) and turns each authorized
// invitation into: an explicit consent notification, an xdg-desktop-portal
// ScreenCast (VIEW) or RemoteDesktop+ScreenCast (CONTROL) grant, a
// gst-launch-1.0 PipeWire→VP8→RTP subprocess and a relay-only, non-trickle
// pion WebRTC offer. Only the executor's directives authorize a session: a
// session absent from the directives, a terminate directive, a SessionService
// PermissionDenied, 30 s without a successful sync, the invitation's
// ends_at, a closed portal session, a logind Session.Lock or
// PrepareForSleep for the bound logind session (SESSION_LOCKED) or the local
// stop action each end capture and input immediately.
//
// Boundaries and non-goals:
//   - The helper never runs as root, never touches privileged paths and never
//     supplies local identity; the executor derives it from SO_PEERCRED and
//     logind.
//   - There is no X11 or other capture path that bypasses the portal dialog;
//     missing notification actions, a missing ScreenCast (or, for CONTROL,
//     RemoteDesktop) portal interface, or a desktop whose locks lindm cannot
//     observe (XDG_CURRENT_DESKTOP outside the lock-observability table in
//     lock.go) end the session UNAVAILABLE before the consent prompt;
//     CONTROL is never downgraded to VIEW. Missing GStreamer elements end it
//     UNAVAILABLE after consent.
//   - The cursor is embedded into the stream when the portal offers the
//     embedded cursor mode, otherwise the hidden mode is requested. The
//     metadata mode is never used because the encoder pipeline does not
//     composite cursor metadata, so on such portals the operator sees no cursor.
//   - No clipboard, file transfer, audio, recording or session extension.
//   - Input is limited to absolute pointer motion, the three primary buttons,
//     discrete wheel steps and keys from a fixed KeyboardEvent.code table; power
//     and sleep keys are not mapped.
package desktop
