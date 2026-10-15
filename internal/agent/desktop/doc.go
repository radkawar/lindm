// SPDX-License-Identifier: Apache-2.0

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
//     missing or unverified notification actions, a missing ScreenCast (or,
//     for CONTROL and all COSMIC requests, RemoteDesktop) portal interface,
//     or a desktop whose locks lindm cannot observe (XDG_CURRENT_DESKTOP
//     outside the lock-observability table in lock.go) end the session
//     UNAVAILABLE before the consent prompt;
//     CONTROL is never downgraded to VIEW. Missing GStreamer elements end it
//     UNAVAILABLE after consent.
//   - Every session also passes the desktop qualification table
//     (qualification.go), keyed on the executor-observed logind session
//     type and XDG_CURRENT_DESKTOP. GNOME retains its native Tier 1/2
//     admission; COSMIC admits only VIEW, CONTROL and keyboard after its
//     portal and safe-consent checks. KDE Plasma Wayland and every X11 session
//     need the device policy's kde_plasma or x11 gate (LIMITED: VIEW and non-input
//     capabilities; ON: also CONTROL and input capabilities) and are
//     narrowed to the capabilities their own native lanes qualified, with
//     exact refusal and withholding reasons. X11 uses the same portal
//     session and persistent local stop; nothing falls back to Xlib/XTest.
//   - Experimental Hyprland Wayland and Cinnamon X11 profiles require the
//     exact reviewed deployed fork tuple, verified against root-owned source,
//     active backend executable mappings, portal selection and locker process
//     identity/start time. Desktop names or installed packages alone never
//     admit them. Only VIEW, CONTROL and keyboard are qualified; Cinnamon
//     additionally keeps the signed X11 gate. Stock platform support and
//     server-side lock-action policy are unchanged.
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
//     marker on its existing reliable ordered input channel; VIEW has no input
//     channel and uses the typed report. A report only exposes a witness matching
//     its atomically published selection, and end revokes cached publication.
//   - Operator messages use the bound user's notifier, separate from Stop.
//   - Files default off independently of input and require bounded executor
//     authority plus local approval for each incoming file or a native chooser
//     selection for each outgoing file. Modal approval drains and pauses input
//     and clipboard; cancellation or failed cleanup ends the session rather than
//     resuming remote injection. Only clean local completion creates a new input
//     epoch. Transfers retain same-session-user descriptors, enforce shared
//     MIME/extension and size ceilings, and never auto-open received files.
//     Exact-release admission may disable files without enabling another path.
//   - Recording happens only with the invitation's immutable recording
//     authority and the prompt's explicit disclosure: optional recording is the
//     local user's choice, required recording ends the session when it cannot
//     be disclosed, sealed, indicated or stored. The recorder taps the consented
//     VP8 RTP stream before SRTP, muxes WebM and seals each segment in memory
//     (internal/assistancerecording); nothing is written to disk and nothing
//     is recorded after capture stops.
//   - Reconnect invitations are ordinary fresh invitations that disclose the
//     earlier session; no portal restore token or earlier grant is reused.
//   - Unattended access restores a persistent portal grant only for an
//     employee who opted in locally; the token stays in the user's private
//     state file, a banner precedes the restore, and a dialog, lock, other user
//     or missing opt-in refuses. Optional recording and sound are refused.
//   - Password guidance pauses all remote input and clipboard until the
//     employee's local Resume; nothing detects or answers the prompt.
//   - The pointer overlay is the GNOME Shell extension owned by the shell's
//     own bus name; it draws normalized points only and takes no input. Local
//     Hide is final for the session.
//   - Sound needs local selection of one output and, under ON, a separate
//     microphone choice; local Mute stops capture.
//   - No session extension.
package desktop
