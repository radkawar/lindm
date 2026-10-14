// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/turn/v4"
	"github.com/pion/webrtc/v4"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	turnRealm    = "lindm.test"
	turnUser     = "1900000000:session:device"
	turnPassword = "relay-secret"
)

// startTURN runs a pion/turn relay on 127.0.0.1 whose relayed addresses are
// also on loopback.
func startTURN(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: turnRealm,
		AuthHandler: func(username, realm string, _ net.Addr) ([]byte, bool) {
			if username != turnUser {
				return nil, false
			}
			return turn.GenerateAuthKey(username, realm, turnPassword), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            conn,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	return fmt.Sprintf("turn:%s?transport=udp", conn.LocalAddr().String())
}

func iceServers(url string) []*agentv1.AssistanceIceServer {
	return []*agentv1.AssistanceIceServer{{Urls: []string{url}, Username: turnUser, Credential: turnPassword}}
}

// browserPeer stands in for the console: relay-only, answers the offer.
func browserPeer(t *testing.T, url string) *webrtc.PeerConnection {
	t.Helper()
	settings := webrtc.SettingEngine{}
	settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	media := &webrtc.MediaEngine{}
	if err := media.RegisterDefaultCodecs(); err != nil {
		t.Fatal(err)
	}
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(settings), webrtc.WithMediaEngine(media)).NewPeerConnection(webrtc.Configuration{
		ICEServers:         []webrtc.ICEServer{{URLs: []string{url}, Username: turnUser, Credential: turnPassword}},
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func answer(t *testing.T, pc *webrtc.PeerConnection, offer string) string {
	t.Helper()
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer}); err != nil {
		t.Fatal(err)
	}
	description, err := pc.CreateAnswer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(description); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gathered:
	case <-time.After(10 * time.Second):
		t.Fatal("answer gathering timed out")
	}
	return pc.LocalDescription().SDP
}

func TestPionPeerOffersOnlyRelayCandidatesAndConnects(t *testing.T) {
	url := startTURN(t)
	peer, err := NewPionPeers().NewPeer(PeerConfig{ICEServers: iceServers(url), Input: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	offer, err := peer.Offer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayOnly(offer); err != nil {
		t.Fatalf("offer candidates: %v\n%s", err, offer)
	}
	if strings.Count(offer, "a=fingerprint:sha-256 ") != 1 {
		t.Fatalf("offer must carry exactly one sha-256 fingerprint:\n%s", offer)
	}
	for _, want := range []string{"m=video", "VP8/90000", "a=sendonly", "m=application"} {
		if !strings.Contains(offer, want) {
			t.Fatalf("offer lacks %q:\n%s", want, offer)
		}
	}

	if err := peer.BeginDisplay("monitor-1", 1); err != nil {
		t.Fatal(err)
	}
	browser := browserPeer(t, url)
	received := make(chan struct{})
	browser.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if _, _, err := track.ReadRTP(); err == nil {
			close(received)
		}
	})
	channels := make(chan *webrtc.DataChannel, 1)
	markers := make(chan string, 1)
	browser.OnDataChannel(func(channel *webrtc.DataChannel) {
		channel.OnMessage(func(message webrtc.DataChannelMessage) { markers <- string(message.Data) })
		channels <- channel
	})
	answerSDP := answer(t, browser, offer)
	if err := relayOnly(answerSDP); err != nil {
		t.Fatalf("answer candidates: %v", err)
	}
	if err := peer.Answer(answerSDP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-peer.Connected():
	case <-peer.Failed():
		t.Fatal("peer failed")
	case <-ctx.Done():
		t.Fatal("peer did not connect through the relay")
	}

	// Media: VP8 RTP from the encoder reaches the browser.
	packet := []byte{0x80, rtpPayloadType, 0, 1, 0, 0, 0, 1, 0, 0, 0, 7, 0x10, 0x00, 0x9d, 0x01, 0x2a}
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for seq := uint16(1); ; seq++ {
			select {
			case <-received:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				packet[2], packet[3] = byte(seq>>8), byte(seq)
				_, _ = peer.WriteRTP(packet)
			}
		}
	}()
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal("no RTP reached the browser")
	}

	// Input: the browser's message on lindm-input reaches the helper.
	var channel *webrtc.DataChannel
	select {
	case channel = <-channels:
	case <-ctx.Done():
		t.Fatal("no input data channel")
	}
	if channel.Label() != inputChannelLabel || !channel.Ordered() {
		t.Fatalf("data channel %q ordered=%t", channel.Label(), channel.Ordered())
	}
	opened := make(chan struct{})
	// pion runs the handler immediately when the channel is already open.
	channel.OnOpen(func() { close(opened) })
	select {
	case <-opened:
	case <-ctx.Done():
		t.Fatal("data channel did not open")
	}
	// The production transport sends the same exact timestamp as the packet
	// already received above, over the existing reliable ordered channel.
	frame := DisplayFrame{Display: "monitor-1", Generation: 1, RTPTimestamp: 1}
	if err := peer.PublishDisplayFrame(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-markers:
		if decodeDisplayFrame(t, message) != frame {
			t.Fatalf("transport marker = %s", message)
		}
	case <-ctx.Done():
		t.Fatal("display marker not delivered")
	}
	if err := channel.SendText(`{"t":"key","code":"KeyA","down":true,"display":"monitor-1","generation":1,"epoch":1}`); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-peer.Input():
		if string(message) != `{"t":"key","code":"KeyA","down":true,"display":"monitor-1","generation":1,"epoch":1}` {
			t.Fatalf("input = %q", message)
		}
	case <-ctx.Done():
		t.Fatal("input message not delivered")
	}
	// Switch draining is fixed without weakening overflow's stuck-key defense.
	// With no consumer, overflowing even with a release must still fail closed.
	for range inputQueueSize + 1 {
		if err := channel.SendText(`{"t":"release"}`); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-peer.Failed():
	case <-ctx.Done():
		t.Fatal("input queue overflow did not fail closed")
	}
}

func TestPionPeerViewHasNoDataChannel(t *testing.T) {
	url := startTURN(t)
	peer, err := NewPionPeers().NewPeer(PeerConfig{ICEServers: iceServers(url)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	offer, err := peer.Offer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayOnly(offer); err != nil {
		t.Fatalf("offer candidates: %v", err)
	}
	if strings.Contains(offer, "m=application") || peer.Input() != nil {
		t.Fatalf("VIEW offer carries a data channel:\n%s", offer)
	}
}

func TestPionPeerRequiresICEServers(t *testing.T) {
	if _, err := NewPionPeers().NewPeer(PeerConfig{}); err == nil {
		t.Fatal("peer without relay accepted")
	}
}
