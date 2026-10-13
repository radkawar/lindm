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
//   - Tier1 optional capabilities default off and require named directional
//     product consent, fresh authority, and native portal grants. Clipboard is
//     explicit bounded UTF-8 text on the same RemoteDesktop session, never a
//     root/X11/direct-compositor fallback. Setting a selection is not a paste.
//     Only explicit unsupported/denied clipboard method replies are independent
//     refusals; cancellation, transport failure and invalid session/state abort.
//     Both a successful RequestClipboard and Start's exact true grant are needed.
//   - Typed low-frequency commands have bounded identities/results and never
//     replay side effects. Text exists only in ephemeral session memory.
//   - Input distinguishes printable XKB symbols from physical evdev keys. The
//     pinned public-domain libxkbcommon graphical table supplies canonical legacy
//     symbols without CGo; action/dead/modifier/keypad aliases remain excluded.
//     Symbols absent from the active keymap and arbitrary Unicode/IME insertion
//     are not supported. Monitor switches pause input under a short lock, release
//     held presses, fence coordinates AND keyboards, and retain one RTP timeline.
//   - Display-frame witnesses name the first actually emitted post-mapping RTP
//     timestamp for the exact source/generation. CONTROL also caches/sends this
//     marker on its existing reliable ordered input channel; VIEW has no data
//     channel and uses the typed report. A report only exposes a witness matching
//     its atomically published selection, and end revokes cached publication.
//   - Operator messages use the bound user's notifier, separate from Stop.
//     No file transfer, audio, recording, unattended access or session extension.
package desktop
