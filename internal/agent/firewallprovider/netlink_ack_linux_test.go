//go:build linux

package firewallprovider

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func errorAck(sequence uint32, code int32) netlink.Message {
	data := make([]byte, 20)
	binary.NativeEndian.PutUint32(data, uint32(code))
	return netlink.Message{Header: netlink.Header{Type: netlink.Error, Sequence: sequence}, Data: data}
}

// A foreign writer (firewalld starting beside boot restoration) moving the
// ruleset generation makes nfnetlink refuse BATCH_BEGIN with ERESTART before any
// object is processed; the library surfaces it as a receive error. That refusal
// is retryable, never an unknown outcome, but only ahead of every object ack.
func TestBatchGenerationRefusalIsEffectFree(t *testing.T) {
	restart := &netlink.OpError{Op: "receive", Err: unix.ERESTART}
	if err := receiveFailure(restart, false); !errors.Is(err, errGenerationChanged) || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("generation refusal misclassified: %v", err)
	}
	if err := receiveFailure(restart, true); !errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, errGenerationChanged) {
		t.Fatalf("restart after an applied object hid a possible effect: %v", err)
	}
	if err := receiveFailure(&netlink.OpError{Op: "receive", Err: unix.EEXIST}, false); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("object error not left unknown: %v", err)
	}
}

// Object acknowledgments complete the batch; a repeated success for an object
// (the kernel's module-autoload replay at boot) is tolerated, anything else is not.
func TestBatchAcksAcceptOnlyObjectSuccess(t *testing.T) {
	sent := []netlink.Message{{Header: netlink.Header{Sequence: 10}}, {Header: netlink.Header{Sequence: 11}}, {Header: netlink.Header{Sequence: 12}}, {Header: netlink.Header{Sequence: 13}}}
	acks := newBatchAcks(sent)
	for _, sequence := range []uint32{11, 11, 12} {
		if err := acks.accept(errorAck(sequence, 0)); err != nil {
			t.Fatalf("object acknowledgment %d refused: %v", sequence, err)
		}
	}
	if acks.remaining != 0 {
		t.Fatalf("duplicate acknowledgment counted twice: %d remaining", acks.remaining)
	}
	for name, ack := range map[string]netlink.Message{
		"batch-begin":     errorAck(10, 0),
		"batch-end":       errorAck(13, 0),
		"foreign":         errorAck(99, 0),
		"error-code":      errorAck(11, -int32(unix.EEXIST)),
		"not-error-reply": {Header: netlink.Header{Type: netlink.Done, Sequence: 11}, Data: make([]byte, 4)},
		"short":           {Header: netlink.Header{Type: netlink.Error, Sequence: 11}, Data: []byte{0}},
	} {
		if err := newBatchAcks(sent).accept(ack); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("%s: unexpected acknowledgment accepted: %v", name, err)
		}
	}
}
