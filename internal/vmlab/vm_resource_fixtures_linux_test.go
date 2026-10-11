//go:build linux

package vmlab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A client that reads the HTTP/1.0 response to EOF with ragged-EOF detection
// enabled, as APT 3.0's OpenSSL transport does, must see the TLS close_notify
// alert rather than a bare TCP close.
const raggedEOFClient = `import socket, ssl, sys
context = ssl.create_default_context(cafile=sys.argv[1])
raw = socket.create_connection(("127.0.0.1", int(sys.argv[2])), timeout=20)
conn = context.wrap_socket(raw, server_hostname="127.0.0.1", suppress_ragged_eofs=False)
conn.sendall(b"GET /dists/stable/Release HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
data = b""
try:
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
except ssl.SSLEOFError as error:
    sys.exit("ragged TLS EOF: %s" % error)
conn.close()
if not data.startswith(b"HTTP/1.0 200 ") or not data.endswith(b"fixture release\n"):
    sys.exit("unexpected response %r" % data)
`

func TestResourceRepositoryServerSendsTLSCloseNotify(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is the guest fixture server's own runtime")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "repo/dists/stable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "repo/dists/stable/Release"), []byte("fixture release\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "https.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "https.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %T", listener.Addr())
	}
	port := strconv.Itoa(address.Port)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resourceRepositoryServer, "18449") || !strings.Contains(resourceRepositoryServer, resourceFixtureRoot) {
		t.Fatal("fixture server no longer binds the lane's repository root and port")
	}
	source := strings.NewReplacer("18449", port, resourceFixtureRoot, root).Replace(resourceRepositoryServer)
	server := exec.Command(python, "-c", source)
	var serverOutput strings.Builder
	server.Stdout, server.Stderr = &serverOutput, &serverOutput
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Process.Kill()
		_ = server.Wait()
	})
	for deadline := time.Now().Add(10 * time.Second); ; {
		conn, err := net.Dial("tcp", "127.0.0.1:"+port)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fixture server did not listen: %v: %s", err, serverOutput.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	client := exec.Command(python, "-c", raggedEOFClient, filepath.Join(root, "https.crt"), port)
	if output, err := client.CombinedOutput(); err != nil {
		t.Fatalf("fixture repository connection ended without TLS close_notify: %v: %s", err, output)
	}
}
