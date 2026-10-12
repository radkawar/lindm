package desktop

import "testing"

// GNOME queued a new request unseen behind a resident "ended" banner (org
// demo finance-desktop, Fedora 44): each prompt withdraws the previous one.
func TestNewPromptWithdrawsPreviousEndedNotice(t *testing.T) {
	deps := &sessionDeps{}
	first := &fakeNotice{result: make(chan string, 1), closed: make(chan struct{})}
	second := &fakeNotice{result: make(chan string, 1), closed: make(chan struct{})}
	if err := deps.replaceEndedNotice(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := deps.replaceEndedNotice(t.Context(), second); err != nil || !first.isClosed() || second.isClosed() {
		t.Fatalf("a newer end notice did not replace the older: %v", err)
	}
	if err := deps.replaceEndedNotice(t.Context(), nil); err != nil || !second.isClosed() {
		t.Fatalf("a prompt left the end notice resident: %v", err)
	}
}
