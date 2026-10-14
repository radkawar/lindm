// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

type assistanceFileSafetyNode struct {
	assistanceFileObservation
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	Links      uint64 `json:"links"`
	ModifiedNS int64  `json:"modified_ns"`
	ChangedNS  int64  `json:"changed_ns"`
	LinkTarget string `json:"link_target"`
}

type assistanceFileSafetyDisk struct {
	UID             uint32                               `json:"uid"`
	Home            string                               `json:"account_home"`
	Downloads       string                               `json:"downloads"`
	DirectoryDevice uint64                               `json:"directory_device"`
	DirectoryInode  uint64                               `json:"directory_inode"`
	DirectoryMode   uint32                               `json:"directory_mode"`
	Nodes           map[string]*assistanceFileSafetyNode `json:"nodes"`
	Staging         []string                             `json:"staging"`
}

type assistanceFileSafetyRefusal struct {
	RequestID  string           `json:"requestId"`
	Boundary   string           `json:"boundary"`
	Code       string           `json:"code"`
	Reason     string           `json:"reason"`
	HTTPStatus int              `json:"httpStatus"`
	Actor      *assistanceActor `json:"actor"`
	Metadata   struct {
		Name   string `json:"name"`
		Size   string `json:"size"`
		MIME   string `json:"mimeType"`
		SHA256 string `json:"sha256"`
	} `json:"metadata"`
	Audit *assistanceAuditEvidence `json:"audit,omitempty"`
	// A lexical rejection is not evidence that the file-authority handler ran.
	AuditScope  string                        `json:"audit_scope"`
	InputBefore *agentv1.AssistanceInputState `json:"input_before"`
	InputAfter  *agentv1.AssistanceInputState `json:"input_after"`
}

type assistanceFileSafetyCheck struct {
	Kind        string                       `json:"kind"`
	Name        string                       `json:"name"`
	SourceMIME  string                       `json:"independent_source_mime,omitempty"`
	Hostile     *assistanceFileSafetyHostile `json:"hostile_sender,omitempty"`
	Attempt     *assistanceFileAttempt       `json:"attempt,omitempty"`
	Refusal     *assistanceFileSafetyRefusal `json:"refusal,omitempty"`
	Before      *assistanceFileSafetyDisk    `json:"before"`
	After       *assistanceFileSafetyDisk    `json:"after"`
	InputBefore *assistanceFixtureState      `json:"native_input_before"`
	InputAfter  *assistanceFixtureState      `json:"native_input_after"`
}

type assistanceFileSafetyProof struct {
	Scenario        string                       `json:"scenario"`
	Actor           *assistanceActor             `json:"actor"`
	Session         *adminv1.AssistanceSession   `json:"session"`
	ProtectedSource *assistanceEvidenceFile      `json:"protected_source,omitempty"`
	CollisionName   string                       `json:"collision_name,omitempty"`
	SymlinkName     string                       `json:"symlink_name,omitempty"`
	ReferentName    string                       `json:"referent_name,omitempty"`
	Fresh           *assistanceFileSafetyDisk    `json:"fresh,omitempty"`
	Seeded          *assistanceFileSafetyDisk    `json:"seeded,omitempty"`
	Cleaned         *assistanceFileSafetyDisk    `json:"cleaned,omitempty"`
	Checks          []*assistanceFileSafetyCheck `json:"checks"`
}

type assistanceFileSafetyWireMetadata struct {
	Name   string `json:"name"`
	Size   string `json:"size"`
	MIME   string `json:"mimeType"`
	SHA256 string `json:"sha256"`
}

type assistanceFileSafetyWirePrepared struct {
	RequestID     string                           `json:"requestId"`
	SessionID     string                           `json:"sessionId"`
	Actor         *assistanceActor                 `json:"actor"`
	Metadata      assistanceFileSafetyWireMetadata `json:"metadata"`
	CarrierSHA256 string                           `json:"carrierSHA256"`
	PayloadSHA256 string                           `json:"payloadSHA256"`
}

type assistanceFileSafetyWireFrame struct {
	Kind            string `json:"kind"`
	OriginalSHA256  string `json:"originalSHA256"`
	ForwardedSHA256 string `json:"forwardedSHA256"`
	OriginalBytes   int    `json:"originalBytes"`
	ForwardedBytes  int    `json:"forwardedBytes"`
	Original        []byte `json:"original,omitempty"`
	Forwarded       []byte `json:"forwarded,omitempty"`
}

type assistanceFileSafetyWireIncoming struct {
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	Data   []byte `json:"data,omitempty"`
}

type assistanceFileSafetyWireObserved struct {
	RequestID     string                             `json:"requestId"`
	SessionID     string                             `json:"sessionId"`
	Actor         *assistanceActor                   `json:"actor"`
	CarrierSHA256 string                             `json:"carrierSHA256"`
	PayloadSHA256 string                             `json:"payloadSHA256"`
	RPCOriginal   assistanceFileSafetyWireMetadata   `json:"rpcOriginal"`
	RPCForwarded  assistanceFileSafetyWireMetadata   `json:"rpcForwarded"`
	RPCForwards   int                                `json:"rpcForwards"`
	ChannelLabel  string                             `json:"channelLabel"`
	Ordered       bool                               `json:"ordered"`
	Reliable      bool                               `json:"reliable"`
	Outbound      []assistanceFileSafetyWireFrame    `json:"outbound"`
	Inbound       []assistanceFileSafetyWireIncoming `json:"inbound"`
	Restored      bool                               `json:"restored"`
}

type assistanceFileSafetyHostile struct {
	Carrier          assistanceEvidenceFile             `json:"carrier"`
	CarrierMIME      string                             `json:"carrier_mime"`
	Prepared         *assistanceFileSafetyWirePrepared  `json:"prepared"`
	ExpectedOutbound []assistanceFileSafetyWireFrame    `json:"expected_outbound"`
	ExpectedInbound  []assistanceFileSafetyWireIncoming `json:"expected_inbound"`
	Observed         *assistanceFileSafetyWireObserved  `json:"observed"`
}

type assistanceFileSafetyWireTemplate struct {
	Kind      string `json:"kind"`
	Original  []byte `json:"original"`
	Forwarded []byte `json:"forwarded"`
}

type assistanceFileSafetyIncomingTemplate struct {
	Kind string `json:"kind"`
	Data []byte `json:"data"`
}

func (p *assistanceFileSafetyProof) fileArtifacts() []assistanceEvidenceFile {
	var artifacts []assistanceEvidenceFile
	if p.ProtectedSource != nil {
		artifacts = append(artifacts, *p.ProtectedSource)
	}
	for _, check := range p.Checks {
		if check != nil && check.Attempt != nil {
			artifacts = append(artifacts, check.Attempt.Source)
			if check.Attempt.Destination != nil {
				artifacts = append(artifacts, *check.Attempt.Destination)
			}
			if check.Hostile != nil {
				artifacts = append(artifacts, check.Hostile.Carrier)
			}
		}
	}
	return artifacts
}

func (p *assistanceFileSafetyProof) screenshotPaths() []string {
	var paths []string
	for _, check := range p.Checks {
		if check == nil || check.Attempt == nil {
			continue
		}
		for _, path := range []string{check.Attempt.ConsentScreenshot, check.Attempt.HostPickerScreenshot, check.Attempt.GuestPickerScreenshot} {
			if path != "" {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func fileSafetySourceMIME(fixture *assistanceFileFixture) (_ string, err error) {
	file, err := os.Open(fixture.Path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	var prefix [512]byte
	if _, err := io.ReadFull(file, prefix[:]); err != nil {
		return "", err
	}
	contentType, _, err := mime.ParseMediaType(http.DetectContentType(prefix[:]))
	return contentType, err
}

// This observer is independent of the product's reports and storage helpers.
// All filesystem work runs as the consented account, never as root. Cleanup is
// restricted to the nonce paths AND inode identities created by this invocation;
// it does not remove product staging or any unexpected output to hide a failure.
const assistanceFileSafetyScript = `import os,sys,pwd,stat,json,hashlib,re
q=json.loads(sys.argv[1]);uid=os.geteuid()
if uid<=0 or uid!=os.getuid(): raise RuntimeError('nonroot_account_required')
home=pwd.getpwuid(uid).pw_dir
h=os.open(home,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 try: os.mkdir('Downloads',0o700,dir_fd=h);os.fsync(h)
 except FileExistsError: pass
 d=os.open('Downloads',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=h)
 try:
  ds=os.fstat(d)
  if ds.st_uid!=uid or stat.S_IMODE(ds.st_mode)&0o022: raise RuntimeError('unsafe_downloads')
  names=q['names']
  if not names or len(names)>3 or len(set(names))!=len(names): raise RuntimeError('invalid_probe_names')
  for n in names:
   if re.fullmatch(r'lindm-file-[a-f0-9]{24}\.(txt|exe)',n) is None: raise RuntimeError('invalid_probe_name')
  def node(fd,n):
   r={'exists':False,'regular':False,'symlink':False,'uid':0,'mode':0,'bytes':0,'sha256':'','staging':[],'device':0,'inode':0,'links':0,'modified_ns':0,'changed_ns':0,'link_target':''}
   try: s=os.stat(n,dir_fd=fd,follow_symlinks=False)
   except FileNotFoundError: return r
   r.update(exists=True,regular=stat.S_ISREG(s.st_mode),symlink=stat.S_ISLNK(s.st_mode),uid=s.st_uid,mode=stat.S_IMODE(s.st_mode),bytes=s.st_size,device=s.st_dev,inode=s.st_ino,links=s.st_nlink,modified_ns=s.st_mtime_ns,changed_ns=s.st_ctime_ns)
   if stat.S_ISLNK(s.st_mode): r['link_target']=os.readlink(n,dir_fd=fd)
   if stat.S_ISREG(s.st_mode):
    f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
    with os.fdopen(f,'rb') as src:
     before=os.fstat(src.fileno())
     if (before.st_dev,before.st_ino)!=(s.st_dev,s.st_ino): raise RuntimeError('identity_changed')
     digest=hashlib.sha256()
     for chunk in iter(lambda:src.read(65536),b''): digest.update(chunk)
     after=os.fstat(src.fileno())
     if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns): raise RuntimeError('bytes_changed')
     r['sha256']=digest.hexdigest()
   return r
  op=q['operation']
  if op=='seed':
   if len(names)!=3: raise RuntimeError('invalid_seed')
   data=sys.stdin.buffer.read(4097)
   if not data or len(data)>4096: raise RuntimeError('invalid_seed_bytes')
   created=[]
   try:
    for n in [names[0],names[2]]:
     fd=os.open(n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
     s=os.fstat(fd);created.append((n,s.st_dev,s.st_ino))
     with os.fdopen(fd,'wb') as dst: dst.write(data);dst.flush();os.fchmod(dst.fileno(),0o600);os.fsync(dst.fileno())
    os.symlink(names[2],names[1],dir_fd=d)
    s=os.stat(names[1],dir_fd=d,follow_symlinks=False);created.append((names[1],s.st_dev,s.st_ino))
    os.fsync(d)
   except BaseException:
    for n,dev,ino in reversed(created):
     s=os.stat(n,dir_fd=d,follow_symlinks=False)
     if (s.st_dev,s.st_ino)==(dev,ino): os.unlink(n,dir_fd=d)
    os.fsync(d)
    raise
  elif op=='cleanup':
   expected=q['expected']
   for n in names:
    actual=node(d,n);saved=expected[n]
    if actual!=saved: raise RuntimeError('cleanup_identity_or_bytes_changed')
   for n in names: os.unlink(n,dir_fd=d)
   os.fsync(d)
  elif op!='observe': raise RuntimeError('invalid_operation')
  nodes={n:node(d,n) for n in names}
  if q.get('observe_home'):
   for n in names: nodes['../'+n]=node(h,n)
  print(json.dumps({'uid':uid,'account_home':home,'downloads':os.path.join(home,'Downloads'),'directory_device':ds.st_dev,'directory_inode':ds.st_ino,'directory_mode':stat.S_IMODE(ds.st_mode),'nodes':nodes,'staging':sorted(n for n in os.listdir(d) if n.startswith('.lindm-transfer-'))}))
 finally: os.close(d)
finally: os.close(h)
`

func (r *assistanceRun) fileSafetyDisk(ctx context.Context, operation string, names []string, home bool, fixture *assistanceFileFixture, expected *assistanceFileSafetyDisk) (_ *assistanceFileSafetyDisk, err error) {
	args := map[string]any{"operation": operation, "names": names, "observe_home": home}
	if expected != nil {
		args["expected"] = expected.Nodes
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	var file *os.File
	if fixture != nil {
		file, err = os.Open(fixture.Path)
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, file.Close()) }()
	}
	// A nil *os.File inside io.Reader is not a nil reader.
	command := r.desktop.rootScript("as python3 -c " + nativeQuote(assistanceFileSafetyScript) + " " + nativeQuote(string(encoded)))
	var data []byte
	if file == nil {
		data, err = r.vm.guest.run(ctx, command, nil, 32<<10, 30*time.Second)
	} else {
		data, err = r.vm.guest.run(ctx, command, file, 32<<10, 30*time.Second)
	}
	if err != nil {
		return nil, err
	}
	var disk assistanceFileSafetyDisk
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, fmt.Errorf("decode independent safety disk observation: %w", err)
	}
	return &disk, nil
}

func (r *assistanceRun) fileSafetyLive(ctx context.Context, scenario *assistanceScenarioEvidence) (*adminv1.AssistanceSession, error) {
	return r.waitSession(ctx, scenario, 20*time.Second, "live file safety authority", func(session *adminv1.AssistanceSession) bool {
		return session.GetState() == adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE && session.GetInputState().GetEpoch() > 0 && !session.GetInputState().GetPaused()
	})
}

func (r *assistanceRun) fileSafetyRecovery(ctx context.Context, check *assistanceFileSafetyCheck) (err error) {
	if err := r.browser.call(ctx, "control", nil, nil, 30*time.Second); err != nil {
		return err
	}
	check.InputBefore, err = r.waitFixture(ctx, "file safety input baseline", func(*assistanceFixtureState) bool { return true })
	if err != nil {
		return err
	}
	check.InputAfter, err = r.pointerWitness(ctx, 0, 0.5, 0.6)
	return err
}

func (r *assistanceRun) fileSafetyAdmission(ctx context.Context, scenario *assistanceScenarioEvidence, kind string) (*assistanceFileSafetyCheck, error) {
	nonce, err := assistanceNonce()
	if err != nil {
		return nil, err
	}
	extension := ".txt"
	if kind == "extension" {
		extension = ".exe"
	}
	check := &assistanceFileSafetyCheck{Kind: kind, Name: "lindm-file-" + nonce + extension, Refusal: new(assistanceFileSafetyRefusal)}
	check.Before, err = r.fileSafetyDisk(ctx, "observe", []string{check.Name}, kind == "path", nil, nil)
	if err != nil {
		return nil, err
	}
	before, err := r.fileSafetyLive(ctx, scenario)
	if err != nil {
		return nil, err
	}
	if err := r.browser.call(ctx, "fileRefuse", map[string]any{"boundary": kind, "name": check.Name}, check.Refusal, 45*time.Second); err != nil {
		return nil, err
	}
	check.Refusal.InputBefore = before.GetInputState()
	check.Refusal.AuditScope = "file_authority"
	if kind == "path" {
		// device.Service.handlerOptions installs connectrpc.com/validate ahead
		// of StartAssistanceFileTransfer: no Lindm-Reason or domain audit exists.
		check.Refusal.AuditScope = "schema_before_file_authority"
	} else {
		check.Refusal.Audit, err = r.authorizationAudit(ctx, scenario.SessionID, scenario.OperatorID, "assistance.file.deny", check.Refusal.RequestID)
		if err != nil {
			return nil, err
		}
	}
	check.After, err = r.fileSafetyDisk(ctx, "observe", []string{check.Name}, kind == "path", nil, nil)
	if err != nil {
		return nil, err
	}
	after, err := r.fileSafetyLive(ctx, scenario)
	if err != nil {
		return nil, err
	}
	check.Refusal.InputAfter = after.GetInputState()
	if err := r.fileSafetyRecovery(ctx, check); err != nil {
		return nil, err
	}
	return check, nil
}

func (r *assistanceRun) fileSafetyUpload(ctx context.Context, scenario *assistanceScenarioEvidence, fixture *assistanceFileFixture, kind string, names []string) (*assistanceFileSafetyCheck, error) {
	check := &assistanceFileSafetyCheck{Kind: kind, Name: fixture.Name}
	var err error
	check.SourceMIME, err = fileSafetySourceMIME(fixture)
	if err != nil {
		return nil, err
	}
	check.Before, err = r.fileSafetyDisk(ctx, "observe", names, false, nil, nil)
	if err != nil {
		return nil, err
	}
	check.Attempt, err = r.fileUpload(ctx, scenario, fixture, true, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED)
	if err != nil {
		return nil, err
	}
	check.After, err = r.fileSafetyDisk(ctx, "observe", names, false, nil, nil)
	if err != nil {
		return nil, err
	}
	if err := r.fileSafetyRecovery(ctx, check); err != nil {
		return nil, err
	}
	return check, nil
}

// This is a native outgoing source-policy probe, not an incoming receiver probe.
// The ordinary console refuses PDF before an incoming RPC under text-only policy.
// Here the real guest chooser opens PDF bytes under a .txt name; the helper's
// retained-descriptor content check must refuse them before disclosing any bytes.
func (r *assistanceRun) fileSafetySourceMIME(ctx context.Context, scenario *assistanceScenarioEvidence, fixture *assistanceFileFixture) (*assistanceFileSafetyCheck, error) {
	check := &assistanceFileSafetyCheck{Kind: "mime-source", Name: fixture.Name}
	var err error
	check.SourceMIME, err = fileSafetySourceMIME(fixture)
	if err != nil {
		return nil, err
	}
	check.Before, err = r.fileSafetyDisk(ctx, "observe", []string{fixture.Name}, false, nil, nil)
	if err != nil {
		return nil, err
	}
	check.Attempt, err = r.fileDownloadExpected(ctx, scenario, fixture, chooserSelect, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED)
	if err != nil {
		return nil, err
	}
	check.After, err = r.fileSafetyDisk(ctx, "observe", []string{fixture.Name}, false, nil, nil)
	if err != nil {
		return nil, err
	}
	if err := r.fileSafetyRecovery(ctx, check); err != nil {
		return nil, err
	}
	return check, nil
}

func fileSafetyReadPayload(fixture *assistanceFileFixture) (_ []byte, err error) {
	file, err := os.Open(fixture.Path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data := make([]byte, 512)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	if !info.Mode().IsRegular() || info.Size() != 512 || hex.EncodeToString(digest[:]) != fixture.SHA256 {
		return nil, errors.New("hostile sender fixture changed after independent binding")
	}
	return data, nil
}

func fileSafetyWireMetadata(fixture assistanceEvidenceFile) assistanceFileSafetyWireMetadata {
	digest, _ := hex.DecodeString(fixture.SHA256)
	return assistanceFileSafetyWireMetadata{Name: fixture.Path, Size: "512", MIME: "text/plain", SHA256: base64.StdEncoding.EncodeToString(digest)}
}

func fileSafetyFrameDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func fileSafetyWireTemplates(request string, carrier, payload *assistanceFileFixture, hostile *assistanceFileSafetyHostile) ([]assistanceFileSafetyWireTemplate, []assistanceFileSafetyIncomingTemplate, error) {
	var encoded [2][3][]byte
	for i, fixture := range []*assistanceFileFixture{carrier, payload} {
		data, err := fileSafetyReadPayload(fixture)
		if err != nil {
			return nil, nil, err
		}
		digest := sha256.Sum256(data)
		metadata := &agentv1.AssistanceFileMetadata{Name: fixture.Name, Size: 512, Sha256: digest[:], MimeType: "text/plain"}
		frames := []*agentv1.AssistanceFileFrame{
			{RequestId: request, Body: &agentv1.AssistanceFileFrame_Start{Start: metadata}},
			{RequestId: request, Body: &agentv1.AssistanceFileFrame_Chunk{Chunk: &agentv1.AssistanceFileChunk{Data: data}}},
			{RequestId: request, Body: &agentv1.AssistanceFileFrame_End{End: &agentv1.AssistanceFileEnd{Size: 512, Sha256: digest[:]}}},
		}
		for j, frame := range frames {
			encoded[i][j], err = proto.Marshal(frame)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	var outbound []assistanceFileSafetyWireTemplate
	for i, kind := range []string{"start", "chunk", "end"} {
		original, forwarded := encoded[0][i], encoded[1][i]
		outbound = append(outbound, assistanceFileSafetyWireTemplate{Kind: kind, Original: original, Forwarded: forwarded})
		hostile.ExpectedOutbound = append(hostile.ExpectedOutbound, assistanceFileSafetyWireFrame{Kind: kind, OriginalSHA256: fileSafetyFrameDigest(original), ForwardedSHA256: fileSafetyFrameDigest(forwarded), OriginalBytes: len(original), ForwardedBytes: len(forwarded)})
	}
	frames := []*agentv1.AssistanceFileFrame{
		{RequestId: request, Body: &agentv1.AssistanceFileFrame_Ready{Ready: &agentv1.AssistanceFileReady{}}},
		{RequestId: request, Body: &agentv1.AssistanceFileFrame_Cancel{Cancel: &agentv1.AssistanceFileCancel{Reason: "file_type_denied"}}},
	}
	var inbound []assistanceFileSafetyIncomingTemplate
	for i, kind := range []string{"ready", "cancel"} {
		data, err := proto.Marshal(frames[i])
		if err != nil {
			return nil, nil, err
		}
		inbound = append(inbound, assistanceFileSafetyIncomingTemplate{Kind: kind, Data: data})
		hostile.ExpectedInbound = append(hostile.ExpectedInbound, assistanceFileSafetyWireIncoming{Kind: kind, SHA256: fileSafetyFrameDigest(data), Bytes: len(data)})
	}
	return outbound, inbound, nil
}

// The authenticated adversarial sender changes only actual outgoing RPC/frame
// input. It never supplies a Ready, receipt, terminal result or denial audit.
func (r *assistanceRun) fileSafetyReceiverMIME(ctx context.Context, scenario *assistanceScenarioEvidence) (_ *assistanceFileSafetyCheck, err error) {
	carrier, err := r.fileFixture(512, false)
	if err != nil {
		return nil, err
	}
	payload, err := r.fileFixture(512, true)
	if err != nil {
		return nil, err
	}
	check := &assistanceFileSafetyCheck{Kind: "mime-receiver-hostile", Name: payload.Name, Attempt: new(assistanceFileAttempt), Hostile: new(assistanceFileSafetyHostile)}
	check.Hostile.Carrier, err = r.bindFileFixture(carrier)
	if err != nil {
		return nil, err
	}
	check.Attempt.Source, err = r.bindFileFixture(payload)
	if err != nil {
		return nil, err
	}
	check.SourceMIME, err = fileSafetySourceMIME(payload)
	if err != nil {
		return nil, err
	}
	check.Hostile.CarrierMIME, err = fileSafetySourceMIME(carrier)
	if err != nil {
		return nil, err
	}
	names := []string{payload.Name, carrier.Name}
	check.Before, err = r.fileSafetyDisk(ctx, "observe", names, false, nil, nil)
	if err != nil {
		return nil, err
	}
	check.Attempt.Before, err = r.observeGuestFile(ctx, payload.Name, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		err = errors.Join(err, r.browser.call(cleanup, "fileSafetyReceiverRestore", nil, nil, 15*time.Second))
	}()
	if err := r.browser.call(ctx, "fileSafetyReceiverPrepare", map[string]any{"sessionId": scenario.SessionID, "carrier": carrier.Name, "payload": payload.Name}, &check.Hostile.Prepared, 40*time.Second); err != nil {
		return nil, err
	}
	if err := verifyFileSafetyPrepared(scenario, check); err != nil {
		return nil, err
	}
	request := check.Hostile.Prepared.RequestID
	outbound, inbound, err := fileSafetyWireTemplates(request, carrier, payload, check.Hostile)
	if err != nil {
		return nil, err
	}
	started, err := r.fileReport(ctx, "fileSafetyReceiverForward", map[string]any{"requestId": request, "outbound": outbound, "inbound": inbound})
	if err != nil {
		return nil, err
	}
	if started.GetRequestId() != request || started.GetDirection() != agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER {
		return nil, errors.New("hostile Start response changed its authenticated request identity")
	}
	attempt := check.Attempt
	attempt.Paused, err = r.filePaused(ctx, scenario, request)
	if err != nil {
		return nil, err
	}
	attempt.ConsentScreenshot, attempt.ConsentOCR, err = r.fileIncomingDecision(ctx, scenario, request, payload.Name, true)
	if err != nil {
		return nil, err
	}
	attempt.Report, err = r.waitFile(ctx, request, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED)
	if err != nil {
		return nil, err
	}
	attempt.After, err = r.observeGuestFile(ctx, payload.Name, true)
	if err != nil {
		return nil, err
	}
	attempt.Resumed, err = r.fileResumed(ctx, scenario, attempt.Paused)
	if err != nil {
		return nil, err
	}
	attempt.Audit, err = r.authorizationAudit(ctx, scenario.SessionID, scenario.OperatorID, "assistance.file.deny", request)
	if err != nil {
		return nil, err
	}
	if err := r.browser.call(ctx, "fileSafetyReceiverFinish", map[string]any{"requestId": request}, &check.Hostile.Observed, 35*time.Second); err != nil {
		return nil, err
	}
	check.After, err = r.fileSafetyDisk(ctx, "observe", names, false, nil, nil)
	if err != nil {
		return nil, err
	}
	if err := r.fileSafetyRecovery(ctx, check); err != nil {
		return nil, err
	}
	return check, nil
}

func (r *assistanceRun) fileSafetyScenario(ctx context.Context, scenario *assistanceScenarioEvidence) (_ *assistanceFileSafetyProof, err error) {
	if scenario == nil || (scenario.Name != "files-filesystem" && scenario.Name != "files-limits") {
		return nil, errors.New("unknown native file safety scenario")
	}
	proof := &assistanceFileSafetyProof{Scenario: scenario.Name}
	proof.Session, err = r.fileSafetyLive(ctx, scenario)
	if err != nil {
		return nil, err
	}
	if err := r.browser.call(ctx, "identity", nil, &proof.Actor, 15*time.Second); err != nil {
		return nil, err
	}
	if err := r.startFixture(ctx, 1); err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		err = errors.Join(err, r.stopFixture(cleanup))
	}()
	restoreReference, err := r.useFixtureReference(ctx)
	if err != nil {
		return nil, err
	}
	defer restoreReference()
	if err := r.browser.call(ctx, "control", nil, nil, time.Minute); err != nil {
		return nil, err
	}
	var marker struct {
		Head int `json:"head"`
	}
	if err := r.browser.call(ctx, "marker", nil, &marker, 45*time.Second); err != nil {
		return nil, err
	}
	if marker.Head != 0 {
		return nil, errors.New("file safety fixture is not on the selected display")
	}
	if scenario.Name == "files-limits" {
		for _, kind := range []string{"size", "extension"} {
			check, err := r.fileSafetyAdmission(ctx, scenario, kind)
			if err != nil {
				return nil, err
			}
			proof.Checks = append(proof.Checks, check)
		}
		fixture, err := r.fileFixture(512, true)
		if err != nil {
			return nil, err
		}
		check, err := r.fileSafetySourceMIME(ctx, scenario, fixture)
		if err != nil {
			return nil, err
		}
		proof.Checks = append(proof.Checks, check)
		receiver, err := r.fileSafetyReceiverMIME(ctx, scenario)
		if err != nil {
			return nil, err
		}
		proof.Checks = append(proof.Checks, receiver)
	} else if err := r.fileSafetyFilesystem(ctx, scenario, proof); err != nil {
		return nil, err
	}
	return proof, verifyFileSafety(scenario, proof)
}

func (r *assistanceRun) fileSafetyFilesystem(ctx context.Context, scenario *assistanceScenarioEvidence, proof *assistanceFileSafetyProof) (err error) {
	collision, err := r.fileFixture(512, false)
	if err != nil {
		return err
	}
	symlink, err := r.fileFixture(512, false)
	if err != nil {
		return err
	}
	protected, err := r.fileFixture(384, false)
	if err != nil {
		return err
	}
	bound, err := r.bindFileFixture(protected)
	if err != nil {
		return err
	}
	proof.ProtectedSource = &bound
	proof.CollisionName, proof.SymlinkName, proof.ReferentName = collision.Name, symlink.Name, protected.Name
	names := []string{collision.Name, symlink.Name, protected.Name}
	proof.Fresh, err = r.fileSafetyDisk(ctx, "observe", names, false, nil, nil)
	if err != nil {
		return err
	}
	for _, node := range proof.Fresh.Nodes {
		if node.Exists {
			return errors.New("filesystem safety nonce path already exists")
		}
	}
	proof.Seeded, err = r.fileSafetyDisk(ctx, "seed", names, false, protected, nil)
	if err != nil {
		return err
	}
	defer func() {
		// Never remove a collision while an unexpectedly unfinished product
		// transfer could still publish. Failed probes retain their private
		// fixtures in the disposable guest for diagnosis; they cannot pass.
		if err != nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		var cleanupErr error
		proof.Cleaned, cleanupErr = r.fileSafetyDisk(cleanup, "cleanup", names, false, nil, proof.Seeded)
		err = errors.Join(err, cleanupErr)
	}()
	for i, fixture := range []*assistanceFileFixture{collision, symlink} {
		check, err := r.fileSafetyUpload(ctx, scenario, fixture, []string{"collision", "symlink"}[i], names)
		if err != nil {
			return err
		}
		proof.Checks = append(proof.Checks, check)
	}
	check, err := r.fileSafetyAdmission(ctx, scenario, "path")
	if err != nil {
		return err
	}
	proof.Checks = append(proof.Checks, check)
	return nil
}

func fileSafetyName(name string) bool {
	if !strings.HasPrefix(name, "lindm-file-") || (filepath.Ext(name) != ".txt" && filepath.Ext(name) != ".exe") {
		return false
	}
	nonce := strings.TrimSuffix(strings.TrimPrefix(name, "lindm-file-"), filepath.Ext(name))
	decoded, err := hex.DecodeString(nonce)
	return err == nil && len(decoded) == 12 && nonce == strings.ToLower(nonce)
}

func verifyFileSafetyDisk(scenario *assistanceScenarioEvidence, disk *assistanceFileSafetyDisk, names []string, home bool) error {
	if disk == nil || disk.UID != scenario.LocalSession.UID || !filepath.IsAbs(disk.Home) || disk.Home == "/" || filepath.Clean(disk.Home) != disk.Home || disk.Downloads != filepath.Join(disk.Home, "Downloads") || disk.DirectoryInode == 0 || disk.DirectoryMode&0022 != 0 || disk.Staging == nil || len(disk.Staging) != 0 {
		return errors.New("safety disk observation lacks account-owned Downloads or has staging")
	}
	count := len(names)
	if home {
		count *= 2
	}
	if len(disk.Nodes) != count {
		return errors.New("safety disk observation omits a probed path")
	}
	for _, name := range names {
		keys := []string{name}
		if home {
			keys = append(keys, "../"+name)
		}
		for _, key := range keys {
			node := disk.Nodes[key]
			if !fileSafetyName(name) || node == nil || node.Staging == nil || len(node.Staging) != 0 {
				return errors.New("safety disk node is missing or not nonce-scoped")
			}
			if !node.Exists {
				if node.Regular || node.Symlink || node.UID != 0 || node.Mode != 0 || node.Bytes != 0 || node.SHA256 != "" || node.Device != 0 || node.Inode != 0 || node.Links != 0 || node.ModifiedNS != 0 || node.ChangedNS != 0 || node.LinkTarget != "" {
					return errors.New("absent safety node carries contradictory metadata")
				}
				continue
			}
			if node.UID != disk.UID || node.Inode == 0 || node.Links != 1 || node.ModifiedNS <= 0 || node.ChangedNS <= 0 || node.Regular == node.Symlink {
				return errors.New("safety node lacks stable user-owned regular-file or symlink identity")
			}
			if node.Regular {
				digest, err := hex.DecodeString(node.SHA256)
				if err != nil || len(digest) != 32 || node.Mode != 0600 || node.LinkTarget != "" {
					return errors.New("protected file lacks independent hash and private mode")
				}
			} else if node.Mode != 0777 || node.SHA256 != "" || !fileSafetyName(node.LinkTarget) || node.Bytes != uint64(len(node.LinkTarget)) {
				return errors.New("protected symlink lacks its exact independently read target")
			}
		}
	}
	return nil
}

func sameFileSafetyDirectory(before, after *assistanceFileSafetyDisk) bool {
	return before != nil && after != nil && before.UID == after.UID && before.Home == after.Home && before.Downloads == after.Downloads && before.DirectoryDevice == after.DirectoryDevice && before.DirectoryInode == after.DirectoryInode && before.DirectoryMode == after.DirectoryMode
}

func sameFileSafetyDisk(before, after *assistanceFileSafetyDisk) bool {
	if !sameFileSafetyDirectory(before, after) || len(before.Nodes) != len(after.Nodes) || len(before.Staging) != 0 || len(after.Staging) != 0 {
		return false
	}
	for name, a := range before.Nodes {
		b := after.Nodes[name]
		if a == nil || b == nil || !sameGuestFile(&a.assistanceFileObservation, &b.assistanceFileObservation) || a.Device != b.Device || a.Inode != b.Inode || a.Links != b.Links || a.ModifiedNS != b.ModifiedNS || a.ChangedNS != b.ChangedNS || a.LinkTarget != b.LinkTarget {
			return false
		}
	}
	return true
}

func verifyFileSafetyAudit(scenario *assistanceScenarioEvidence, audit *assistanceAuditEvidence, request, reason, result string) error {
	if audit == nil || !vmValidID(audit.ID) || audit.OccurredAt.IsZero() || audit.ActorID != scenario.OperatorID || audit.ResourceID != scenario.SessionID || audit.TargetDeviceID != scenario.DeviceID || audit.Action != "assistance.file.deny" || audit.Details["request"] != request || audit.Details["reason"] != reason || audit.Details["result"] != result {
		return errors.New("file safety denial lacks exact typed actor/request audit")
	}
	return nil
}

func verifyFileSafetyAdmission(scenario *assistanceScenarioEvidence, check *assistanceFileSafetyCheck) error {
	refusal := check.Refusal
	if refusal == nil || check.Attempt != nil || check.SourceMIME != "" || !vmValidID(refusal.RequestID) || refusal.Boundary != check.Kind || refusal.HTTPStatus != 400 || refusal.Metadata.MIME != "text/plain" || refusal.Metadata.SHA256 != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		return errors.New("file admission lacks the actual authenticated request and exact refusal")
	}
	if err := verifyAssistanceActor(scenario, refusal.Actor); err != nil {
		return err
	}
	if !slices.Contains(refusal.Actor.Permissions, "remote_assistance.files") || refusal.InputBefore.GetEpoch() == 0 || refusal.InputBefore.GetPaused() || refusal.InputAfter.GetPaused() || refusal.InputAfter.GetEpoch() != refusal.InputBefore.GetEpoch() {
		return errors.New("file admission was not a live authorized creator with uninterrupted input")
	}
	name, size := check.Name, "1"
	if check.Kind == "size" {
		size = "1025"
	}
	if check.Kind == "path" {
		name = "../" + name
		if refusal.Code != "invalid_argument" || refusal.Reason != "" || refusal.Audit != nil || refusal.AuditScope != "schema_before_file_authority" {
			return errors.New("lexical refusal falsely claims domain authority or a domain reason/audit")
		}
	} else {
		if refusal.Code != "failed_precondition" || refusal.Reason != "assistance_file_policy" || refusal.AuditScope != "file_authority" {
			return errors.New("file admission failed for a reason other than the configured file policy")
		}
		if err := verifyFileSafetyAudit(scenario, refusal.Audit, refusal.RequestID, "assistance_file_policy", "denied"); err != nil {
			return err
		}
	}
	if refusal.Metadata.Name != name || refusal.Metadata.Size != size || (check.Kind == "extension") != strings.HasSuffix(check.Name, ".exe") {
		return errors.New("file admission did not send the intended single invalid metadata field")
	}
	for _, node := range check.Before.Nodes {
		if node.Exists {
			return errors.New("file admission did not target fresh absent nonce paths")
		}
	}
	return nil
}

func verifyFileSafetyTransfer(scenario *assistanceScenarioEvidence, check *assistanceFileSafetyCheck) error {
	attempt := check.Attempt
	if check.Refusal != nil {
		return errors.New("native transfer was substituted with admission-only refusal")
	}
	if err := verifyFileAttempt(scenario, attempt); err != nil {
		return err
	}
	digest, digestErr := hex.DecodeString(attempt.Source.SHA256)
	if digestErr != nil || len(digest) != 32 || attempt.Source.Bytes != 512 || attempt.Source.Path != check.Name || !strings.HasSuffix(check.Name, ".txt") || attempt.Report.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED || attempt.ReceivedScreenshot != "" || attempt.ReceivedOCR != "" {
		return errors.New("native safety refusal lacks independently bound source bytes or exact failed state")
	}
	if check.Kind == "mime-source" {
		return verifyFileSafetySourceMIME(scenario, check)
	}
	reason, wantMIME := "file_transfer_failed", "text/plain" // RENAME_NOREPLACE EEXIST has no more specific public reason.
	if check.Kind == "mime-receiver-hostile" {
		reason, wantMIME = "file_type_denied", "application/pdf"
		if err := verifyFileSafetyHostile(scenario, check); err != nil {
			return err
		}
	}
	report := attempt.Report
	if check.SourceMIME != wantMIME || report.GetDirection() != agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER || report.GetReason() != reason || report.GetBytesTransferred() != 512 || attempt.ConsentScreenshot == "" || !fileNoticeVisible(attempt.ConsentOCR, scenario.OperatorDisplay, check.Name, false) || attempt.Destination != nil || attempt.DestinationAbsent {
		return errors.New("native filesystem refusal lacks full streaming, real local approval or exact receiver failure")
	}
	if err := verifyFileSafetyAudit(scenario, attempt.Audit, report.GetRequestId(), reason, "failed"); err != nil {
		return err
	}
	details := attempt.Audit.Details
	if details["direction"] != "operator_to_user" || details["bytes"] != "512" || details["reserved_bytes"] != "512" || details["sha256"] != attempt.Source.SHA256 || details["authorized_sha256"] != attempt.Source.SHA256 || details["sha256_origin"] != "authorized_request" || details["mime_type"] != "text/plain" {
		return errors.New("native refusal audit was not attributed to the entire authorized stream")
	}
	before, after := check.Before.Nodes[check.Name], check.After.Nodes[check.Name]
	if !sameGuestFile(attempt.Before, &before.assistanceFileObservation) || !sameGuestFile(attempt.After, &after.assistanceFileObservation) {
		return errors.New("transfer observations disagree with independent safety observer")
	}
	if check.Kind == "mime-receiver-hostile" {
		// The earlier outgoing refusal conservatively reserved one full KiB.
		if before.Exists || details["max_file_bytes"] != "1024" || details["max_session_bytes"] != "3072" || details["allowed_mime_types"] != "text/plain" || details["allowed_extensions"] != ".txt" {
			return errors.New("incoming receiver MIME refusal lacks narrowed remaining policy or absent output")
		}
	}
	return nil
}

func verifyFileSafetyPrepared(scenario *assistanceScenarioEvidence, check *assistanceFileSafetyCheck) error {
	hostile := check.Hostile
	if hostile == nil || hostile.Prepared == nil || check.Attempt == nil || !fileSafetyName(hostile.Carrier.Path) || hostile.Carrier.Path == check.Name || hostile.Carrier.Bytes != 512 || hostile.CarrierMIME != "text/plain" {
		return errors.New("hostile sender lacks distinct bound carrier and payload fixtures")
	}
	carrierDigest, err := hex.DecodeString(hostile.Carrier.SHA256)
	if err != nil || len(carrierDigest) != 32 || hostile.Carrier.SHA256 == check.Attempt.Source.SHA256 {
		return errors.New("hostile sender carrier digest is absent or identical to payload")
	}
	p := hostile.Prepared
	if !vmValidID(p.RequestID) || p.SessionID != scenario.SessionID || p.CarrierSHA256 != hostile.Carrier.SHA256 || p.PayloadSHA256 != check.Attempt.Source.SHA256 || p.Metadata != fileSafetyWireMetadata(hostile.Carrier) {
		return errors.New("hostile sender lacks its observed original UI request")
	}
	if err := verifyAssistanceActor(scenario, p.Actor); err != nil {
		return err
	}
	if !slices.Contains(p.Actor.Permissions, "remote_assistance.files") {
		return errors.New("hostile sender lacks authenticated file authority")
	}
	return nil
}

func fileSafetyDecodedFrame(data []byte, request string) (*agentv1.AssistanceFileFrame, error) {
	if len(data) == 0 || len(data) > 1024 {
		return nil, errors.New("hostile wire observation exceeded the fixed probe bound")
	}
	frame := new(agentv1.AssistanceFileFrame)
	if err := proto.Unmarshal(data, frame); err != nil {
		return nil, err
	}
	canonical, err := proto.Marshal(frame)
	if err != nil || frame.GetRequestId() != request || len(frame.ProtoReflect().GetUnknown()) != 0 || !slices.Equal(canonical, data) {
		return nil, errors.New("hostile wire frame identity or canonical encoding changed")
	}
	return frame, nil
}

func verifyFileSafetyHostile(scenario *assistanceScenarioEvidence, check *assistanceFileSafetyCheck) error {
	if err := verifyFileSafetyPrepared(scenario, check); err != nil {
		return err
	}
	h := check.Hostile
	observed := h.Observed
	request := check.Attempt.Report.GetRequestId()
	if observed == nil || request != h.Prepared.RequestID || observed.RequestID != request || observed.SessionID != scenario.SessionID || observed.CarrierSHA256 != h.Carrier.SHA256 || observed.PayloadSHA256 != check.Attempt.Source.SHA256 || observed.RPCOriginal != fileSafetyWireMetadata(h.Carrier) || observed.RPCForwarded != fileSafetyWireMetadata(check.Attempt.Source) || observed.RPCForwards != 1 || observed.ChannelLabel != "lindm-files" || !observed.Ordered || !observed.Reliable || !observed.Restored || len(observed.Outbound) != 3 || len(observed.Inbound) != 2 || len(h.ExpectedOutbound) != 3 || len(h.ExpectedInbound) != 2 {
		return errors.New("receiver MIME proof lacks bounded real RPC/DTLS wire mutation and restoration")
	}
	if err := verifyAssistanceActor(scenario, observed.Actor); err != nil {
		return err
	}
	if !slices.Contains(observed.Actor.Permissions, "remote_assistance.files") {
		return errors.New("receiver MIME actor lacks file authority")
	}
	for _, node := range check.Before.Nodes {
		if node.Exists {
			return errors.New("hostile MIME sender did not target absent carrier and payload paths")
		}
	}
	for i, kind := range []string{"start", "chunk", "end"} {
		got, expected := observed.Outbound[i], h.ExpectedOutbound[i]
		if got.Kind != kind || expected.Kind != kind || got.OriginalBytes != len(got.Original) || got.ForwardedBytes != len(got.Forwarded) || got.OriginalSHA256 != fileSafetyFrameDigest(got.Original) || got.ForwardedSHA256 != fileSafetyFrameDigest(got.Forwarded) || got.OriginalSHA256 != expected.OriginalSHA256 || got.ForwardedSHA256 != expected.ForwardedSHA256 || got.OriginalBytes != expected.OriginalBytes || got.ForwardedBytes != expected.ForwardedBytes {
			return errors.New("hostile outbound telemetry differs from actual bounded frame bytes")
		}
		for side, data := range [][]byte{got.Original, got.Forwarded} {
			source := h.Carrier
			if side == 1 {
				source = check.Attempt.Source
			}
			frame, err := fileSafetyDecodedFrame(data, request)
			if err != nil {
				return err
			}
			switch kind {
			case "start":
				file := frame.GetStart()
				if file.GetName() != source.Path || file.GetSize() != 512 || file.GetMimeType() != "text/plain" || hex.EncodeToString(file.GetSha256()) != source.SHA256 {
					return errors.New("hostile Start frame is not exactly the authenticated metadata")
				}
			case "chunk":
				chunk := frame.GetChunk()
				if chunk.GetOffset() != 0 || len(chunk.GetData()) != 512 || fileSafetyFrameDigest(chunk.GetData()) != source.SHA256 {
					return errors.New("hostile sender did not send the actual bound bytes at offset zero")
				}
				wantMIME := "text/plain"
				if side == 1 {
					wantMIME = "application/pdf"
				}
				actual, _, err := mime.ParseMediaType(http.DetectContentType(chunk.GetData()))
				if err != nil || actual != wantMIME {
					return errors.New("hostile wire bytes do not contain the independently expected MIME mismatch")
				}
			case "end":
				end := frame.GetEnd()
				if end.GetSize() != 512 || hex.EncodeToString(end.GetSha256()) != source.SHA256 {
					return errors.New("hostile End did not commit the actual payload hash and size")
				}
			}
		}
	}
	for i, kind := range []string{"ready", "cancel"} {
		got, expected := observed.Inbound[i], h.ExpectedInbound[i]
		if got.Kind != kind || expected.Kind != kind || got.Bytes != len(got.Data) || got.SHA256 != fileSafetyFrameDigest(got.Data) || got.Bytes != expected.Bytes || got.SHA256 != expected.SHA256 {
			return errors.New("receiver readiness or MIME cancellation lacks actual incoming frame evidence")
		}
		frame, err := fileSafetyDecodedFrame(got.Data, request)
		if err != nil {
			return err
		}
		if kind == "ready" && frame.GetReady() == nil || kind == "cancel" && frame.GetCancel().GetReason() != "file_type_denied" {
			return errors.New("receiver did not provide real readiness then exact MIME cancellation")
		}
	}
	return nil
}

func verifyFileSafetySourceMIME(scenario *assistanceScenarioEvidence, check *assistanceFileSafetyCheck) error {
	attempt := check.Attempt
	report := attempt.Report
	if check.SourceMIME != "application/pdf" || report.GetDirection() != agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER || report.GetReason() != "file_type_denied" || report.GetBytesTransferred() != 0 || attempt.ConsentScreenshot != "" || attempt.ConsentOCR != "" || attempt.HostPickerTitle == "" || attempt.HostPickerScreenshot == "" || attempt.GuestPickerScreenshot == "" {
		return errors.New("native source MIME rejection lacks real pickers and the exact pre-disclosure content refusal")
	}
	if err := verifyFileSafetyAudit(scenario, attempt.Audit, report.GetRequestId(), "file_type_denied", "failed"); err != nil {
		return err
	}
	for _, source := range []*assistanceFileObservation{attempt.Before, attempt.After} {
		if !source.Exists || !source.Regular || source.Symlink || source.UID != scenario.LocalSession.UID || source.Mode != 0400 || source.Bytes != 512 || source.SHA256 != attempt.Source.SHA256 {
			return errors.New("native MIME source lacks independent unchanged guest PDF bytes")
		}
	}
	if check.Before.Nodes[check.Name].Exists {
		return errors.New("native source MIME probe unexpectedly had a Downloads output")
	}
	if attempt.DestinationAbsent {
		if attempt.Destination != nil {
			return errors.New("absent MIME destination contradicts its artifact")
		}
	} else if attempt.Destination == nil || attempt.Destination.Path != "saved-"+check.Name || attempt.Destination.Bytes != 0 || attempt.Destination.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		return errors.New("native source MIME denial disclosed bytes or lacks an independently bound empty destination")
	}
	details := attempt.Audit.Details
	if details["direction"] != "user_to_operator" || details["bytes"] != "0" || details["reserved_bytes"] != "1024" || details["sha256"] != "" || details["authorized_sha256"] != "" || details["sha256_origin"] != "authorized_request" || details["mime_type"] != "" || details["max_file_bytes"] != "1024" || details["max_session_bytes"] != "4096" || details["allowed_mime_types"] != "text/plain" || details["allowed_extensions"] != ".txt" {
		return errors.New("native source MIME audit lacks exact narrowed policy or falsely claims verified disclosure")
	}
	return nil
}

func verifyFileSafety(scenario *assistanceScenarioEvidence, proof *assistanceFileSafetyProof) error {
	if scenario == nil || proof == nil || proof.Scenario != scenario.Name || (scenario.Name != "files-filesystem" && scenario.Name != "files-limits") || scenario.LocalSession == nil || scenario.LocalSession.UID == 0 || !vmValidID(scenario.SessionID) || !vmValidID(scenario.DeviceID) {
		return errors.New("file safety proof is incomplete or belongs to another scenario")
	}
	if err := verifyAssistanceActor(scenario, proof.Actor); err != nil {
		return err
	}
	session := proof.Session
	if !slices.Contains(proof.Actor.Permissions, "remote_assistance.files") || session.GetId() != scenario.SessionID || session.GetDeviceId() != scenario.DeviceID || session.GetOperatorId() != scenario.OperatorID || session.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE || session.GetInputState().GetEpoch() == 0 || session.GetInputState().GetPaused() {
		return errors.New("file safety proof lacks authenticated live creator authority")
	}
	for _, policy := range []*agentv1.AssistancePolicy{session.GetEffectiveCapabilities(), session.GetGrantedCapabilities().GetPolicy()} {
		if policy.GetFiles() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON || policy.GetKeyboard() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON || policy.GetFileLimits() == nil {
			return errors.New("file safety session did not grant files and native input")
		}
		if scenario.Name == "files-limits" {
			limits := policy.GetFileLimits()
			if limits.GetMaxFileBytes() != 1024 || limits.GetMaxSessionBytes() != 4096 || !slices.Equal(limits.GetAllowedMimeTypes(), []string{"text/plain"}) || !slices.Equal(limits.GetAllowedExtensions(), []string{".txt"}) {
				return errors.New("file limits scenario lacks its exact configured policy")
			}
		}
	}
	kinds := []string{"size", "extension", "mime-source", "mime-receiver-hostile"}
	if scenario.Name == "files-filesystem" {
		kinds = []string{"collision", "symlink", "path"}
		if err := verifyFileSafetyProtected(scenario, proof); err != nil {
			return err
		}
	} else if proof.ProtectedSource != nil || proof.Fresh != nil || proof.Seeded != nil || proof.Cleaned != nil || proof.CollisionName != "" || proof.SymlinkName != "" || proof.ReferentName != "" {
		return errors.New("limits proof carries unrelated filesystem fixtures")
	}
	if len(proof.Checks) != len(kinds) {
		return errors.New("file safety proof omits a required native boundary")
	}
	seen := make(map[string]bool, len(kinds))
	for i, check := range proof.Checks {
		if check == nil || check.Kind != kinds[i] || !fileSafetyName(check.Name) {
			return errors.New("file safety proof omitted or substituted a required boundary")
		}
		names := []string{check.Name}
		if check.Kind == "mime-receiver-hostile" {
			if check.Hostile == nil {
				return errors.New("receiver MIME proof lacks explicit hostile sender telemetry")
			}
			names = append(names, check.Hostile.Carrier.Path)
		} else if check.Hostile != nil {
			return errors.New("normal file safety probe falsely carries hostile sender evidence")
		}
		if check.Kind == "collision" || check.Kind == "symlink" {
			names = []string{proof.CollisionName, proof.SymlinkName, proof.ReferentName}
			if check.Name != names[i] || !sameFileSafetyDisk(proof.Seeded, check.Before) {
				return errors.New("filesystem attack was not against its protected seeded target")
			}
		}
		for _, disk := range []*assistanceFileSafetyDisk{check.Before, check.After} {
			if err := verifyFileSafetyDisk(scenario, disk, names, check.Kind == "path"); err != nil {
				return err
			}
		}
		if i > 0 && !sameFileSafetyDirectory(proof.Checks[i-1].After, check.Before) {
			return errors.New("file safety checks changed the account-derived Downloads identity")
		}
		if !sameFileSafetyDisk(check.Before, check.After) {
			return errors.New("refused file changed a disk identity, link, bytes or staging")
		}
		var request string
		if check.Kind == "size" || check.Kind == "extension" || check.Kind == "path" {
			if err := verifyFileSafetyAdmission(scenario, check); err != nil {
				return err
			}
			request = check.Refusal.RequestID
		} else {
			if err := verifyFileSafetyTransfer(scenario, check); err != nil {
				return err
			}
			request = check.Attempt.Report.GetRequestId()
		}
		if seen[request] {
			return errors.New("file safety proof reused a request across boundaries")
		}
		seen[request] = true
		for _, state := range []*assistanceFixtureState{check.InputBefore, check.InputAfter} {
			if err := verifyAssistanceFixtureIdentity(state, scenario.LocalSession); err != nil {
				return err
			}
		}
		before, after := check.InputBefore, check.InputAfter
		if before.PID != after.PID || before.Display != after.Display || len(after.Clicks) != len(before.Clicks)+1 || !slices.Equal(before.Clicks, after.Clicks[:len(before.Clicks)]) {
			return errors.New("file refusal lacks a new native input event from the same GTK process")
		}
		if i > 0 {
			previous := proof.Checks[i-1].InputAfter
			if before.PID != previous.PID || before.Display != previous.Display || len(before.Clicks) < len(previous.Clicks) || !slices.Equal(previous.Clicks, before.Clicks[:len(previous.Clicks)]) {
				return errors.New("file safety checks reused or replaced native input evidence")
			}
		}
		if err := verifyAssistancePointer(after.Clicks[len(before.Clicks)], 0, 0.5, 0.6); err != nil {
			return err
		}
	}
	return nil
}

func verifyFileSafetyProtected(scenario *assistanceScenarioEvidence, proof *assistanceFileSafetyProof) error {
	names := []string{proof.CollisionName, proof.SymlinkName, proof.ReferentName}
	if names[0] == names[1] || names[0] == names[2] || names[1] == names[2] || proof.ProtectedSource == nil || proof.ProtectedSource.Path != names[2] || proof.ProtectedSource.Bytes != 384 {
		return errors.New("filesystem proof lacks three distinct nonce paths and original sentinel bytes")
	}
	for _, disk := range []*assistanceFileSafetyDisk{proof.Fresh, proof.Seeded, proof.Cleaned} {
		if err := verifyFileSafetyDisk(scenario, disk, names, false); err != nil {
			return err
		}
	}
	if !sameFileSafetyDirectory(proof.Fresh, proof.Seeded) {
		return errors.New("filesystem fixture was not seeded into the freshly observed Downloads")
	}
	if !sameFileSafetyDisk(proof.Fresh, proof.Cleaned) {
		return errors.New("filesystem proof lacks observed nonce-only cleanup")
	}
	for _, name := range names {
		if proof.Fresh.Nodes[name].Exists {
			return errors.New("filesystem proof reused an existing user path")
		}
	}
	for _, name := range []string{names[0], names[2]} {
		node := proof.Seeded.Nodes[name]
		if !node.Regular || node.SHA256 != proof.ProtectedSource.SHA256 || node.Bytes != 384 {
			return errors.New("protected collision target or referent lacks independently bound original bytes")
		}
	}
	link := proof.Seeded.Nodes[names[1]]
	if !link.Symlink || link.LinkTarget != names[2] {
		return errors.New("filesystem proof lacks an actual symlink to its protected referent")
	}
	return nil
}
