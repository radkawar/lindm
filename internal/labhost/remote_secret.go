package labhost

import (
	"fmt"
	"path/filepath"
)

// remoteSecretFlag reports lane flags whose files are credentials. They are
// staged apart from ordinary inputs so a retained run directory never keeps
// them: the remote host-exec removes them when the lane ends (also when the
// controller's session closes), and the controller removes them again when the
// run ends, whether it succeeded, failed or was interrupted.
func remoteSecretFlag(name string) bool {
	return name == "redhat-token-file"
}

// RemoteSecretDirectory is the run directory's credential staging location.
func RemoteSecretDirectory(run string) string {
	return filepath.Join(run, "secret")
}

func removeRemoteSecretsCommand(run string) string {
	return "rm -rf -- " + QuoteShell(RemoteSecretDirectory(run))
}

// secret stages one credential file for this run only.
func (s *remoteStage) secret(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	dir := RemoteSecretDirectory(s.remote)
	if err := s.mkdir(dir); err != nil {
		return "", err
	}
	target := filepath.Join(dir, filepath.Base(absolute))
	if err := s.sync(absolute, target); err != nil {
		return "", fmt.Errorf("stage credential: %w", err)
	}
	return target, nil
}
