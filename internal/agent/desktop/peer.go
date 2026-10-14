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
)

const (
	inputChannelLabel    = "lindm-input"
	gatherTimeout        = 10 * time.Second
	sctpMaxMessageSize   = 1024
	sctpMaxReceiveBuffer = 64 << 10
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
	return peer, nil
}

type pionPeer struct {
	pc            *webrtc.PeerConnection
	track         *webrtc.TrackLocalStaticRTP
	gatherTimeout time.Duration
	packet        rtp.Packet
	input         chan []byte
	frames        displayFrames

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
	channel.OnMessage(func(message webrtc.DataChannelMessage) {
		if len(message.Data) == 0 || len(message.Data) > maxInputMessageBytes {
			return
		}
		select {
		case p.input <- append([]byte(nil), message.Data...):
		default:
			// Dropping a release can leave a held key indefinitely. Fail closed
			// on queue overflow; session cleanup releases all attempted presses.
			p.failedOnce.Do(func() { close(p.failed) })
		}
	})
	return nil
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
	err := p.pc.Close()
	<-p.rtcpDone
	if err != nil {
		return fmt.Errorf("close peer connection: %w", err)
	}
	return nil
}
