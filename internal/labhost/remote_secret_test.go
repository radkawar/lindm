package labhost

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The Red Hat offline token is staged only under the run's secret directory,
// which the end-of-run cleanup removes even when the run's other state is kept.
func TestRemoteCredentialStagingIsEphemeral(t *testing.T) {
	if !remoteSecretFlag("redhat-token-file") {
		t.Fatal("Red Hat token staged as an ordinary retained input")
	}
	for _, name := range []string{"manifest", "public-key", "rejections", "advisories"} {
		if remoteSecretFlag(name) {
			t.Fatalf("%s treated as a credential", name)
		}
	}
	run := filepath.Join(t.TempDir(), "run-abc")
	stage := &remoteStage{ctx: t.Context(), remote: run, stderr: os.Stderr, copied: map[string]string{}}
	token := filepath.Join(t.TempDir(), "redhat-offline-token")
	if err := os.WriteFile(token, []byte("not-a-real-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	staged, err := stage.secret(token)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(staged) != RemoteSecretDirectory(run) {
		t.Fatalf("credential staged at %s, outside the secret directory", staged)
	}
	info, err := os.Stat(staged)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("staged credential mode = %v, %v", info, err)
	}
	retained := filepath.Join(run, "records", "record")
	if err := os.MkdirAll(filepath.Dir(retained), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(retained, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("sh", "-c", removeRemoteSecretsCommand(run)).CombinedOutput(); err != nil {
		t.Fatalf("cleanup: %v: %s", err, out)
	}
	if _, err := os.Stat(RemoteSecretDirectory(run)); !os.IsNotExist(err) {
		t.Fatalf("credential directory survived cleanup: %v", err)
	}
	if _, err := os.Stat(retained); err != nil {
		t.Fatalf("cleanup removed retained run state: %v", err)
	}
	if _, err := os.Stat(token); err != nil {
		t.Fatalf("cleanup touched the original credential: %v", err)
	}
}
