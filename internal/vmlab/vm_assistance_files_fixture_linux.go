// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// assistanceFileFixture is a real nonce-bearing operator file. Its independent
// host digest is compared with receiver-computed metadata and guest disk bytes.
type assistanceFileFixture struct {
	Name   string `json:"name"`
	Bytes  uint64 `json:"bytes"`
	SHA256 string `json:"sha256"`
	Path   string `json:"-"`
}

func (r *assistanceRun) fileFixture(bytes int, pdf bool) (_ *assistanceFileFixture, err error) {
	if bytes < 0 || bytes > 16<<20 {
		return nil, errors.New("file fixture exceeds the transfer bound")
	}
	nonce, err := assistanceNonce()
	if err != nil {
		return nil, err
	}
	name := "lindm-file-" + nonce + ".txt"
	path := filepath.Join(r.evidence.dir, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	digest := sha256.New()
	writer := io.MultiWriter(file, digest)
	var chunk [64 << 10]byte
	for n := copy(chunk[:], nonce+"\n"); n < len(chunk); {
		n += copy(chunk[n:], chunk[:n])
	}
	remaining := bytes
	if pdf {
		prefix := []byte("%PDF-1.7\n")
		if remaining < len(prefix) {
			return nil, errors.New("PDF refusal fixture is too small")
		}
		if _, err := writer.Write(prefix); err != nil {
			return nil, err
		}
		remaining -= len(prefix)
	}
	for remaining > 0 {
		n := min(remaining, len(chunk))
		if _, err := writer.Write(chunk[:n]); err != nil {
			return nil, err
		}
		remaining -= n
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if err := file.Chmod(0400); err != nil {
		return nil, err
	}
	return &assistanceFileFixture{Name: name, Bytes: uint64(bytes), SHA256: hex.EncodeToString(digest.Sum(nil)), Path: path}, nil
}

const assistanceFileObserveScript = `import os,sys,stat,hashlib,json,pwd
p=os.path.join(pwd.getpwuid(os.geteuid()).pw_dir,sys.argv[1])
r={"exists":False,"regular":False,"symlink":False,"uid":0,"mode":0,"bytes":0,"sha256":"","staging":[]}
try:
 s=os.lstat(p)
 r.update(exists=True,regular=stat.S_ISREG(s.st_mode),symlink=stat.S_ISLNK(s.st_mode),uid=s.st_uid,mode=stat.S_IMODE(s.st_mode),bytes=s.st_size)
 if stat.S_ISREG(s.st_mode):
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
  h=hashlib.sha256()
  with os.fdopen(fd,'rb') as f:
   if os.fstat(f.fileno()).st_ino != s.st_ino: raise RuntimeError('identity_changed')
   for chunk in iter(lambda:f.read(65536),b''): h.update(chunk)
  r['sha256']=h.hexdigest()
except FileNotFoundError: pass
d=os.path.join(pwd.getpwuid(os.geteuid()).pw_dir,'Downloads')
if os.path.isdir(d): r['staging']=sorted(n for n in os.listdir(d) if n.startswith('.lindm-transfer-'))
print(json.dumps(r))`

type assistanceFileObservation struct {
	Exists  bool     `json:"exists"`
	Regular bool     `json:"regular"`
	Symlink bool     `json:"symlink"`
	UID     uint32   `json:"uid"`
	Mode    uint32   `json:"mode"`
	Bytes   uint64   `json:"bytes"`
	SHA256  string   `json:"sha256"`
	Staging []string `json:"staging"`
}

func assistanceGuestFile(name string, downloads bool) string {
	if downloads {
		return "Downloads/" + name
	}
	return name
}

func (r *assistanceRun) observeGuestFile(ctx context.Context, name string, downloads bool) (*assistanceFileObservation, error) {
	if filepath.Base(name) != name || !strings.HasPrefix(name, "lindm-file-") {
		return nil, errors.New("invalid independent file observation name")
	}
	out, err := r.vm.guest.run(ctx, r.desktop.rootScript("as python3 -c "+nativeQuote(assistanceFileObserveScript)+" "+nativeQuote(assistanceGuestFile(name, downloads))), nil, 16<<10, 30*time.Second)
	if err != nil {
		return nil, err
	}
	var result assistanceFileObservation
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("decode independent native file observation: %w", err)
	}
	return &result, nil
}

const assistanceFileInstallScript = `import os,sys,pwd
p=os.path.join(pwd.getpwuid(os.geteuid()).pw_dir,sys.argv[1])
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as f:
 for chunk in iter(lambda:sys.stdin.buffer.read(65536),b''): f.write(chunk)
 f.flush();os.fsync(f.fileno())
os.chmod(p,0o400)`

func (r *assistanceRun) installGuestFile(ctx context.Context, fixture *assistanceFileFixture, downloads bool) (err error) {
	file, err := os.Open(fixture.Path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	command := "as python3 -c " + nativeQuote(assistanceFileInstallScript) + " " + nativeQuote(assistanceGuestFile(fixture.Name, downloads))
	_, err = r.vm.guest.run(ctx, r.desktop.rootScript(command), file, 4096, 30*time.Second)
	return err
}

// chooseGuestFile is independent local-seat input into the real native portal
// chooser. It never calls the product, writes its reports or selects a path on
// behalf of an operator outside the disposable qualification guest.
func (r *assistanceRun) chooseGuestFile(ctx context.Context, fixture *assistanceFileFixture, request string) error {
	out, err := r.vm.guest.run(ctx, r.desktop.rootScript("as python3 -c "+nativeQuote("import os,pwd;print(pwd.getpwuid(os.geteuid()).pw_dir)")), nil, 4096, 15*time.Second)
	if err != nil {
		return err
	}
	home := strings.TrimSpace(string(out))
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return errors.New("native account home is not an absolute clean path")
	}
	keys := func(codes ...string) error {
		values := make([]map[string]any, len(codes))
		for i, code := range codes {
			values[i] = map[string]any{"type": "qcode", "data": code}
		}
		if err := r.vm.guest.qmpCommand(ctx, map[string]any{"execute": "send-key", "id": "local-file-choice", "arguments": map[string]any{"keys": values, "hold-time": 30}}); err != nil {
			return err
		}
		// Let QEMU's scheduled physical key release finish before another
		// press, including repeated letters; this is not a readiness oracle.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(40 * time.Millisecond):
			return nil
		}
	}
	if err := keys("ctrl", "l"); err != nil {
		return err
	}
	for _, ch := range filepath.Join(home, fixture.Name) {
		code := string(ch)
		switch ch {
		case '/':
			code = "slash"
		case '.':
			code = "dot"
		case '-':
			code = "minus"
		default:
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') {
				return errors.New("fixture chooser path is not in the local US-layout alphabet")
			}
		}
		if err := keys(code); err != nil {
			return err
		}
	}
	// GTK 4's chooser resolves a typed location asynchronously: a Return
	// right after typing only selected the file and left Select pending
	// (layers-fedora44-files-08). Return is pressed after the location
	// settles, and again while the request still waits for the selection.
	for attempt := range 3 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		if attempt > 0 {
			report, err := r.fileReport(ctx, "fileState", map[string]any{"requestId": request})
			if err != nil {
				return err
			}
			if report.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_WAITING_CONSENT {
				return nil
			}
		}
		if err := keys("ret"); err != nil {
			return err
		}
	}
	return nil
}
