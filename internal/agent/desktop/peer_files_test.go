// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistancefiles"
)

func TestPionViewFilesUsesSameRelayDTLSWithoutInputChannel(t *testing.T) {
	url := startTURN(t)
	peer, err := NewPionPeers().NewPeer(PeerConfig{ICEServers: []*agentv1.AssistanceIceServer{url.device}, Files: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := peer.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	offer, err := peer.Offer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayOnly(offer); err != nil {
		t.Fatal(err)
	}
	browser := browserPeer(t, url)
	opened := make(chan *webrtc.DataChannel, 2)
	messages := make(chan []byte, 2)
	browser.OnDataChannel(func(channel *webrtc.DataChannel) {
		channel.OnMessage(func(message webrtc.DataChannelMessage) {
			select {
			case messages <- message.Data:
			case <-ctx.Done():
			}
		})
		channel.OnOpen(func() {
			select {
			case opened <- channel:
			case <-ctx.Done():
			}
		})
	})
	answerSDP := answer(t, browser, offer)
	if err := relayOnly(answerSDP); err != nil {
		t.Fatal(err)
	}
	if err := peer.Answer(answerSDP); err != nil {
		t.Fatal(err)
	}
	var channel *webrtc.DataChannel
	select {
	case channel = <-opened:
	case <-ctx.Done():
		t.Fatal("files channel did not open")
	}
	if channel.Label() != "lindm-files" || !channel.Ordered() || channel.MaxRetransmits() != nil || channel.MaxPacketLifeTime() != nil {
		t.Fatal("files channel not reliable and ordered")
	}
	if peer.Input() != nil {
		t.Fatal("VIEW files gained remote input")
	}
	frame := &agentv1.AssistanceFileFrame{RequestId: "69acdf85-c609-46c6-af82-6250f0a141a1", Body: &agentv1.AssistanceFileFrame_Chunk{Chunk: &agentv1.AssistanceFileChunk{Data: bytes.Repeat([]byte("x"), assistancefiles.ChunkBytes)}}}
	encoded, err := proto.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.SendFile(ctx, encoded); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-messages:
		if !bytes.Equal(got, encoded) {
			t.Fatal("helper file frame changed over DTLS")
		}
	case <-ctx.Done():
		t.Fatal("helper frame missing")
	}
	if err := channel.Send(encoded); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-peer.Files():
		if !bytes.Equal(got, encoded) {
			t.Fatal("browser file frame changed over DTLS")
		}
	case <-ctx.Done():
		t.Fatal("browser frame missing")
	}
	if err := peer.SendFile(ctx, make([]byte, assistancefiles.FrameBytes+1)); err == nil {
		t.Fatal("oversize serialized frame sent")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err := peer.SendFile(cancelled, encoded); err == nil {
		t.Fatal("cancelled send succeeded")
	}
	if err := channel.SendText("remote approval"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-peer.Failed():
	case <-ctx.Done():
		t.Fatal("untyped remote approval did not fail closed")
	}
}
