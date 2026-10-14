// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"errors"
	"os"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Notifier is the org.freedesktop.Notifications boundary.
type Notifier interface {
	// Capabilities returns the server's capabilities; an error means no
	// notification server is reachable.
	Capabilities(ctx context.Context) ([]string, error)
	// ServerName returns the server's GetServerInformation name.
	ServerName(ctx context.Context) (string, error)
	// Notify posts a notification.
	Notify(ctx context.Context, notification Notification) (Notice, error)
}

// Notification is one desktop notification.
type Notification struct {
	Summary  string
	Body     string
	Actions  []NotificationAction
	Critical bool
	// Persistent sets expire_timeout 0 (never expire).
	Persistent bool
	// Lifetime sets a bounded expire_timeout so a notice (an operator message or
	// the ended notice) cannot stay resident independently of the stop indicator.
	Lifetime time.Duration
	// Reshow keeps an actionable notification reachable while it awaits an
	// action on a server that can leave it queued behind a banner that has
	// gone (DesktopNotifier.strandsQueuedBanners).
	Reshow bool
}

// NotificationAction is one action button.
type NotificationAction struct {
	Key   string
	Label string
}

// Notice is a posted notification.
type Notice interface {
	// Result delivers exactly one value: the invoked action key, or "" when
	// the notification was closed without an action.
	Result() <-chan string
	// Close withdraws the notification.
	Close(ctx context.Context) error
	// Update replaces the posted notification's content in place (same id),
	// so a banner already on screen shows the new content and its action
	// tracking is unchanged. notification must declare the same actions.
	Update(ctx context.Context, notification Notification) error
}

// Portal is the xdg-desktop-portal boundary.
type Portal interface {
	// Check reports, without any dialog or user interaction, whether the
	// desktop's portal can serve the requested mode and input policy at all.
	// It runs before the consent prompt so an impossible session ends
	// UNAVAILABLE with an exact detail instead of asking for consent it cannot
	// honour; a CONTROL request is never silently downgraded to VIEW.
	Check(ctx context.Context, request PortalRequest) error
	// Open runs the portal dialog after product consent and returns the grant.
	// A user cancellation returns ErrPortalCancelled.
	Open(ctx context.Context, request PortalRequest) (Grant, error)
}

// PortalRequest contains the capabilities named in the product prompt.
// Only Check may run before acceptance; Open requires explicit product consent.
// VIEW never creates a RemoteDesktop session merely to obtain clipboard access.
type PortalRequest struct {
	Mode   agentv1.AssistanceMode
	Policy *agentv1.AssistancePolicy
	// Lifetime ends ongoing transfers independently of the consent dialog.
	Lifetime context.Context
}

// ErrPortalCancelled reports a user-cancelled portal dialog.
var ErrPortalCancelled = errors.New("portal_cancelled")

// Grant is a started portal session.
type Grant interface {
	// Streams contains only monitors returned by the local portal picker.
	Streams() []Stream
	// CursorHidden reports an intentional capture limitation, not input authority.
	CursorHidden() bool
	// SelectStream changes pointer mapping to a granted monitor.
	SelectStream(id string) error
	// ClipboardGranted requires RequestClipboard and clipboard_enabled at Start.
	ClipboardGranted() bool
	ClipboardWrite(ctx context.Context, text string, deadline time.Time) error
	// ClipboardReason identifies an explicit independent native refusal.
	ClipboardReason() string
	ClipboardRead(ctx context.Context) (string, error)
	// ControlGranted reports whether pointer control was granted.
	ControlGranted() bool
	// KeyboardGranted is independent; OFF never requests a keyboard device.
	KeyboardGranted() bool
	// OpenPipeWire returns a PipeWire remote fd restricted to the grant. The
	// caller owns the file.
	OpenPipeWire(ctx context.Context) (*os.File, error)
	// Closed is closed when the portal or compositor ends the session.
	Closed() <-chan struct{}
	// Inject sends one input event; only valid when ControlGranted.
	Inject(ctx context.Context, event InputEvent) error
	// Close ends the portal session.
	Close(ctx context.Context) error
}

// Stream is a PipeWire node with its logical size (0 when unknown).
type Stream struct {
	NodeID        uint32
	ID            string
	Label         string
	Width, Height int
}

// Capturer starts the capture/encode pipeline.
type Capturer interface {
	Start(ctx context.Context, request CaptureRequest) (Capture, error)
}

// CaptureRequest selects the PipeWire stream to encode. Start does not take
// ownership of PipeWire.
type CaptureRequest struct {
	PipeWire *os.File
	Stream   Stream
}

// Capture is a running encoder producing RTP packets.
type Capture interface {
	// ReadPacket reads one RTP packet into buf (at least maxRTPPacket bytes).
	ReadPacket(buf []byte) (int, error)
	// Close stops the encoder and releases its resources.
	Close() error
}

// PeerFactory creates WebRTC peers.
type PeerFactory interface {
	NewPeer(config PeerConfig) (Peer, error)
}

// PeerConfig configures one relay-only peer.
type PeerConfig struct {
	ICEServers []*agentv1.AssistanceIceServer
	// Input adds the reliable ordered "lindm-input" data channel. VIEW has none.
	Input bool
}

// Peer is one WebRTC peer connection that offers a VP8 track.
type Peer interface {
	// Offer creates the complete (non-trickle) offer SDP.
	Offer(ctx context.Context) (string, error)
	// Answer applies the remote answer SDP.
	Answer(sdp string) error
	// WriteRTP sends one RTP packet on the video track. Emitted is false before
	// connection; such packets must never establish a display-frame marker.
	WriteRTP(packet []byte) (emitted bool, err error)
	// BeginDisplay invalidates the cached marker for a newer source generation.
	BeginDisplay(display string, generation uint32) error
	// PublishDisplayFrame caches/sends the first emitted post-mapping timestamp.
	// An old capture's marker can never qualify for a newer source generation.
	PublishDisplayFrame(frame DisplayFrame) error
	// EndDisplayFrames prevents cached replay or publication after session end.
	EndDisplayFrames()
	// Connected is closed once DTLS-SRTP is established.
	Connected() <-chan struct{}
	// Failed is closed when the connection fails or closes.
	Failed() <-chan struct{}
	// Input delivers raw operator messages; nil for VIEW.
	Input() <-chan []byte
	Close() error
}

// EndError carries the assistance end cause a component failure maps to.
type EndError struct {
	Cause  agentv1.AssistanceEndCause
	Detail string
	Err    error
}

func (e *EndError) Error() string {
	if e.Err == nil {
		return e.Detail
	}
	return e.Detail + ": " + e.Err.Error()
}

func (e *EndError) Unwrap() error { return e.Err }

// unavailable maps err to UNAVAILABLE with detail unless err already
// carries a more specific end cause.
func unavailable(detail string, err error) error {
	var endErr *EndError
	if errors.As(err, &endErr) {
		return err
	}
	return &EndError{Cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, Detail: detail, Err: err}
}
