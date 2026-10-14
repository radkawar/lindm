// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"

	"lindm/internal/assistancefiles"
)

const (
	inputChannelLabel      = "lindm-input"
	annotationChannelLabel = "lindm-annotate"
	// opusPayloadType is the audio payload type of the audio pipeline.
	opusPayloadType      = 111
	gatherTimeout        = 10 * time.Second
	sctpMaxMessageSize   = assistancefiles.FrameBytes
	sctpMaxReceiveBuffer = assistancefiles.BufferedBytes
)

// PionPeers creates relay-only pion peers that send one VP8 track.
type PionPeers struct {
	gatherTimeout time.Duration
}

var _ PeerFactory = (*PionPeers)(nil)

// NewPionPeers returns the production peer factory.
func NewPionPeers() *PionPeers {
	return &PionPeers{gatherTimeout: gatherTimeout}
}

// NewPeer builds a peer connection with ICETransportPolicy relay, mDNS
// disabled, a send-only VP8 transceiver and, when config.Input is set, the
// reliable ordered "lindm-input" data channel. VIEW has no data channel.
// Channels opened by the remote are closed.
func (f *PionPeers) NewPeer(config PeerConfig) (Peer, error) {
	if len(config.ICEServers) == 0 {
		return nil, errors.New("peer requires relay ICE servers")
	}
	media := &webrtc.MediaEngine{}
	codec := webrtc.RTPCodecCapability{
		MimeType:  webrtc.MimeTypeVP8,
		ClockRate: 90000,
		RTCPFeedback: []webrtc.RTCPFeedback{
			{Type: "nack"}, {Type: "nack", Parameter: "pli"}, {Type: "ccm", Parameter: "fir"},
		},
	}
	if err := media.RegisterCodec(webrtc.RTPCodecParameters{RTPCodecCapability: codec, PayloadType: rtpPayloadType}, webrtc.RTPCodecTypeVideo); err != nil {
		return nil, fmt.Errorf("register vp8: %w", err)
	}
	opus := webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2, SDPFmtpLine: "minptime=10;useinbandfec=1"}
	if config.Audio {
		if err := media.RegisterCodec(webrtc.RTPCodecParameters{RTPCodecCapability: opus, PayloadType: opusPayloadType}, webrtc.RTPCodecTypeAudio); err != nil {
			return nil, fmt.Errorf("register opus: %w", err)
		}
	}
	registry := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(media, registry); err != nil {
		return nil, fmt.Errorf("register interceptors: %w", err)
	}
	settings := webrtc.SettingEngine{}
	settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	settings.SetSCTPMaxMessageSize(sctpMaxMessageSize)
	settings.SetSCTPMaxReceiveBufferSize(sctpMaxReceiveBuffer)
	api := webrtc.NewAPI(webrtc.WithMediaEngine(media), webrtc.WithInterceptorRegistry(registry), webrtc.WithSettingEngine(settings))

	servers := make([]webrtc.ICEServer, 0, len(config.ICEServers))
	for _, server := range config.ICEServers {
		servers = append(servers, webrtc.ICEServer{
			URLs:       append([]string(nil), server.GetUrls()...),
			Username:   server.GetUsername(),
			Credential: server.GetCredential(),
		})
	}
	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers:         servers,
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
		BundlePolicy:       webrtc.BundlePolicyMaxBundle,
	})
	if err != nil {
		return nil, fmt.Errorf("create peer connection: %w", err)
	}
	peer := &pionPeer{
		pc:            pc,
		gatherTimeout: f.gatherTimeout,
		connected:     make(chan struct{}),
		failed:        make(chan struct{}),
		rtcpDone:      make(chan struct{}),
	}
	if err := peer.setup(codec, config.Input); err != nil {
		return nil, errors.Join(err, pc.Close())
	}
	if config.Files {
		if err := peer.setupFiles(); err != nil {
			return nil, errors.Join(err, peer.Close())
		}
	}
	if config.Annotation {
		if err := peer.setupAnnotation(); err != nil {
			return nil, errors.Join(err, peer.Close())
		}
	}
	if config.Audio {
		if err := peer.setupAudio(opus); err != nil {
			return nil, errors.Join(err, peer.Close())
		}
	}
	return peer, nil
}

type pionPeer struct {
	pc            *webrtc.PeerConnection
	track         *webrtc.TrackLocalStaticRTP
	gatherTimeout time.Duration
	packet        rtp.Packet
	input         chan []byte
	inputMu       sync.Mutex
	inputEpoch    uint32
	inputPaused   bool
	frames        displayFrames
	files         chan []byte
	fileChannel   *webrtc.DataChannel
	fileOpen      chan struct{}
	fileLow       chan struct{}
	fileSendMu    sync.Mutex
	annotations   chan []byte
	audio         *webrtc.TrackLocalStaticRTP
	audioPacket   rtp.Packet

	connected     chan struct{}
	connectedOnce sync.Once
	failed        chan struct{}
	failedOnce    sync.Once
	rtcpDone      chan struct{}
}

var _ Peer = (*pionPeer)(nil)

func (p *pionPeer) setup(codec webrtc.RTPCodecCapability, input bool) error {
	track, err := webrtc.NewTrackLocalStaticRTP(codec, "screen", "lindm")
	if err != nil {
		return fmt.Errorf("create track: %w", err)
	}
	p.track = track
	transceiver, err := p.pc.AddTransceiverFromTrack(track, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly})
	if err != nil {
		return fmt.Errorf("add transceiver: %w", err)
	}
	sender := transceiver.Sender()
	go func() {
		// RTCP must be drained for NACK/report interceptors; Read fails once
		// the connection closes.
		defer close(p.rtcpDone)
		buf := make([]byte, 1500)
		for {
			if _, _, err := sender.Read(buf); err != nil {
				return
			}
		}
	}()
	p.pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		switch state {
		case webrtc.PeerConnectionStateConnected:
			p.connectedOnce.Do(func() { close(p.connected) })
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			p.frames.close()
			p.failedOnce.Do(func() { close(p.failed) })
		default:
		}
	})
	p.pc.OnDataChannel(func(channel *webrtc.DataChannel) {
		_ = channel.Close()
	})
	if !input {
		return nil
	}
	ordered := true
	channel, err := p.pc.CreateDataChannel(inputChannelLabel, &webrtc.DataChannelInit{Ordered: &ordered})
	if err != nil {
		return fmt.Errorf("create input channel: %w", err)
	}
	channel.OnOpen(func() {
		if err := p.frames.open(channel.SendText); err != nil {
			p.failedOnce.Do(func() { close(p.failed) })
		}
	})
	p.input = make(chan []byte, inputQueueSize)
	p.inputEpoch = 1
	channel.OnMessage(func(message webrtc.DataChannelMessage) {
		if message.IsString {
			p.admitInput(message.Data)
		}
	})
	return nil
}

func (p *pionPeer) admitInput(raw []byte) {
	p.inputMu.Lock()
	defer p.inputMu.Unlock()
	if p.inputPaused {
		return
	}
	event, err := parseInput(raw)
	if err != nil || (event.kind != inputRelease && event.Epoch != p.inputEpoch) {
		return
	}
	select {
	case p.input <- raw:
	default:
		p.failedOnce.Do(func() { close(p.failed) })
	}
}

func (p *pionPeer) SetInputState(epoch uint32, paused bool) error {
	p.inputMu.Lock()
	defer p.inputMu.Unlock()
	if epoch == 0 || epoch < p.inputEpoch || (epoch == p.inputEpoch && paused != p.inputPaused) {
		return errors.New("input_epoch_invalid")
	}
	p.inputEpoch, p.inputPaused = epoch, paused
	for {
		select {
		case <-p.input:
		default:
			return nil
		}
	}
}

func (p *pionPeer) setupFiles() error {
	ordered := true
	channel, err := p.pc.CreateDataChannel("lindm-files", &webrtc.DataChannelInit{Ordered: &ordered})
	if err != nil {
		return fmt.Errorf("create files channel: %w", err)
	}
	p.fileChannel = channel
	// The session owns the sole eight-frame queue; this handoff adds none.
	p.files = make(chan []byte)
	p.fileOpen, p.fileLow = make(chan struct{}), make(chan struct{}, 1)
	channel.SetBufferedAmountLowThreshold(assistancefiles.BufferedBytes - assistancefiles.FrameBytes)
	channel.OnBufferedAmountLow(func() {
		select {
		case p.fileLow <- struct{}{}:
		default:
		}
	})
	channel.OnOpen(func() { close(p.fileOpen) })
	channel.OnClose(func() { p.failedOnce.Do(func() { close(p.failed) }) })
	channel.OnError(func(error) { p.failedOnce.Do(func() { close(p.failed) }) })
	channel.OnMessage(func(message webrtc.DataChannelMessage) {
		if message.IsString || len(message.Data) == 0 || len(message.Data) > assistancefiles.FrameBytes {
			p.failedOnce.Do(func() { close(p.failed) })
			return
		}
		select {
		case p.files <- message.Data:
		case <-p.failed:
		}
	})
	return nil
}

func (p *pionPeer) Files() <-chan []byte { return p.files }

// SendFile has one producer, a finite context and event-driven SCTP backpressure.
// It never queues another frame above the negotiated byte ceiling.
func (p *pionPeer) SendFile(ctx context.Context, frame []byte) error {
	if p.fileChannel == nil || len(frame) == 0 || len(frame) > assistancefiles.FrameBytes {
		return errors.New("file_channel_unavailable_or_frame_invalid")
	}
	p.fileSendMu.Lock()
	defer p.fileSendMu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.failed:
		return errors.New("file_channel_failed")
	case <-p.fileOpen:
	}
	for p.fileChannel.BufferedAmount()+uint64(len(frame)) > assistancefiles.BufferedBytes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.failed:
			return errors.New("file_channel_failed")
		case <-p.fileLow:
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return p.fileChannel.Send(frame)
}

func (p *pionPeer) Offer(ctx context.Context) (string, error) {
	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		return "", fmt.Errorf("create offer: %w", err)
	}
	gathered := webrtc.GatheringCompletePromise(p.pc)
	if err := p.pc.SetLocalDescription(offer); err != nil {
		return "", fmt.Errorf("set local description: %w", err)
	}
	timer := time.NewTimer(p.gatherTimeout)
	defer timer.Stop()
	select {
	case <-gathered:
	case <-timer.C:
		return "", errors.New("ice gathering timed out")
	case <-ctx.Done():
		return "", ctx.Err()
	}
	local := p.pc.LocalDescription()
	if local == nil {
		return "", errors.New("missing local description")
	}
	return local.SDP, nil
}

func (p *pionPeer) Answer(sdp string) error {
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdp}); err != nil {
		return fmt.Errorf("set remote description: %w", err)
	}
	return nil
}

// WriteRTP must be called from a single goroutine; it reuses one packet.
func (p *pionPeer) WriteRTP(packet []byte) (bool, error) {
	select {
	case <-p.connected:
	default:
		return false, nil
	}
	if err := p.packet.Unmarshal(packet); err != nil {
		return false, fmt.Errorf("parse rtp: %w", err)
	}
	if err := p.track.WriteRTP(&p.packet); err != nil {
		return false, err
	}
	return true, nil
}

func (p *pionPeer) BeginDisplay(display string, generation uint32) error {
	return p.frames.begin(display, generation)
}

func (p *pionPeer) PublishDisplayFrame(frame DisplayFrame) error {
	return p.frames.publish(frame)
}

func (p *pionPeer) EndDisplayFrames() { p.frames.close() }

func (p *pionPeer) Connected() <-chan struct{} { return p.connected }
func (p *pionPeer) Failed() <-chan struct{}    { return p.failed }
func (p *pionPeer) Input() <-chan []byte       { return p.input }

func (p *pionPeer) Close() error {
	p.frames.close()
	p.failedOnce.Do(func() { close(p.failed) })
	err := p.pc.Close()
	<-p.rtcpDone
	if err != nil {
		return fmt.Errorf("close peer connection: %w", err)
	}
	return nil
}

// setupAnnotation adds the "lindm-annotate" channel. It carries only bounded
// pointer/stroke frames for the local overlay; it is never an input path.
func (p *pionPeer) setupAnnotation() error {
	ordered := true
	channel, err := p.pc.CreateDataChannel(annotationChannelLabel, &webrtc.DataChannelInit{Ordered: &ordered})
	if err != nil {
		return fmt.Errorf("create annotation channel: %w", err)
	}
	p.annotations = make(chan []byte, annotationQueueSize)
	channel.OnMessage(func(message webrtc.DataChannelMessage) {
		if !message.IsString || len(message.Data) > maxAnnotationMessage {
			return
		}
		select {
		case p.annotations <- message.Data:
		default:
			// Overlay frames are droppable; a full queue never blocks media.
		}
	})
	return nil
}

func (p *pionPeer) Annotations() <-chan []byte { return p.annotations }

// setupAudio adds a send-only Opus track for locally selected sound.
func (p *pionPeer) setupAudio(codec webrtc.RTPCodecCapability) error {
	track, err := webrtc.NewTrackLocalStaticRTP(codec, "sound", "lindm")
	if err != nil {
		return fmt.Errorf("create audio track: %w", err)
	}
	transceiver, err := p.pc.AddTransceiverFromTrack(track, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly})
	if err != nil {
		return fmt.Errorf("add audio transceiver: %w", err)
	}
	sender := transceiver.Sender()
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := sender.Read(buf); err != nil {
				return
			}
		}
	}()
	p.audio = track
	return nil
}

// WriteAudioRTP sends one Opus RTP packet; it must be called from a single
// goroutine and drops packets before connection.
func (p *pionPeer) WriteAudioRTP(packet []byte) error {
	if p.audio == nil {
		return errors.New("audio_track_unavailable")
	}
	select {
	case <-p.connected:
	default:
		return nil
	}
	if err := p.audioPacket.Unmarshal(packet); err != nil {
		return fmt.Errorf("parse audio rtp: %w", err)
	}
	return p.audio.WriteRTP(&p.audioPacket)
}
