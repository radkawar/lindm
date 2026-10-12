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
	// Lifetime sets a bounded expire_timeout so a notice cannot stay resident.
	Lifetime time.Duration
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
}

// Portal is the xdg-desktop-portal boundary.
type Portal interface {
	// Check reports, without any dialog or user interaction, whether the
	// desktop's portal can serve mode at all. It runs before the consent
	// prompt so an impossible session ends UNAVAILABLE with an exact detail
	// instead of asking for consent it cannot honour; a CONTROL request is
	// never silently downgraded to VIEW.
	Check(ctx context.Context, mode agentv1.AssistanceMode) error
	// Open runs the portal dialog for mode and returns the grant. A user
	// cancellation returns ErrPortalCancelled.
	Open(ctx context.Context, mode agentv1.AssistanceMode) (Grant, error)
}

// ErrPortalCancelled reports a user-cancelled portal dialog.
var ErrPortalCancelled = errors.New("portal_cancelled")

// Grant is a started portal session.
type Grant interface {
	// Stream is the granted monitor stream.
	Stream() Stream
	// ControlGranted reports whether keyboard and pointer were both granted.
	ControlGranted() bool
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
	// Input adds the ordered "lindm-input" data channel.
	Input bool
}

// Peer is one WebRTC peer connection that offers a VP8 track.
type Peer interface {
	// Offer creates the complete (non-trickle) offer SDP.
	Offer(ctx context.Context) (string, error)
	// Answer applies the remote answer SDP.
	Answer(sdp string) error
	// WriteRTP sends one RTP packet on the video track.
	WriteRTP(packet []byte) error
	// Connected is closed once DTLS-SRTP is established.
	Connected() <-chan struct{}
	// Failed is closed when the connection fails or closes.
	Failed() <-chan struct{}
	// Input delivers raw data-channel messages; nil without a data channel.
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
