// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEntraGraphFaultClosesExistingGraphOnly(t *testing.T) {
	graph, graphPeer := net.Pipe()
	defer func() {
		if err := graphPeer.Close(); err != nil {
			t.Error(err)
		}
	}()
	login, loginPeer := net.Pipe()
	defer func() {
		if err := login.Close(); err != nil {
			t.Error(err)
		}
	}()
	defer func() {
		if err := loginPeer.Close(); err != nil {
			t.Error(err)
		}
	}()
	p := &entraGraphProxy{tunnels: map[net.Conn]bool{graph: true, login: false}}
	if err := p.fail(); err != nil {
		t.Fatal(err)
	}
	if _, err := graphPeer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("existing Graph tunnel survived fault: %v", err)
	}
	if err := loginPeer.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := loginPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected login tunnel data")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("login tunnel was closed by Graph fault: %v", err)
	}
}

func TestEntraProxyRejectsDestinationEscapeAndPostFaultConnect(t *testing.T) {
	p := &entraGraphProxy{failed: true}
	for _, test := range []struct {
		method, host string
		status       int
	}{
		{http.MethodConnect, "attacker.example:443", http.StatusForbidden},
		{http.MethodConnect, "graph.microsoft.com.attacker.example:443", http.StatusForbidden},
		{http.MethodConnect, "graph.microsoft.com:80", http.StatusForbidden},
		{http.MethodGet, "graph.microsoft.com:443", http.StatusForbidden},
		{http.MethodConnect, "graph.microsoft.com:443", http.StatusServiceUnavailable},
	} {
		request := httptest.NewRequest(test.method, "http://localhost/", nil)
		request.Host = test.host
		response := httptest.NewRecorder()
		p.serve(response, request)
		if response.Code != test.status {
			t.Errorf("%s %s: got %d want %d", test.method, test.host, response.Code, test.status)
		}
	}
}
