// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serverdeps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
	"lindm/internal/agent/dnf"
)

// CaptureRPM runs only inside the admitted disposable, RHSM-registered RHEL
// guest. Its native solver deliberately excludes the installed RPM sack, so
// packages on the image never stand in for captured dependency bytes. The
// caller owns image verification, registration cleanup, transfer and a second
// fresh, externally fenced guest for ReplayRPM. Capture alone is not publishable.
func CaptureRPM(ctx context.Context, repository string, input *serverdepsv1.Manifest) (*serverdepsv1.Manifest, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("serverdeps: RHEL closure capture requires a disposable root guest")
	}
	if err := rpmTarget(input); err != nil {
		return nil, err
	}
	if input.GetMaxBytes() == 0 || input.GetMaxBytes() > 16<<30 || input.GetMaxPackages() == 0 || input.GetMaxPackages() > 5000 || len(input.GetRequestedPackages()) == 0 {
		return nil, errors.New("serverdeps: RHEL capture requires explicit closure bounds and packages")
	}
	info, err := os.Lstat(repository)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("serverdeps: RHEL capture requires a private existing repository directory")
	}
	entries, err := os.ReadDir(repository)
	if err != nil || len(entries) != 0 {
		return nil, errors.New("serverdeps: RHEL capture repository must be empty")
	}
	payload, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(input)
	if err != nil {
		return nil, err
	}
	entrypoint, err := os.Open("/usr/bin/dnf")
	if err != nil {
		return nil, err
	}
	shebang, readErr := io.ReadAll(io.LimitReader(entrypoint, 4096))
	if err := errors.Join(readErr, entrypoint.Close()); err != nil {
		return nil, err
	}
	interpreter, err := dnf.Interpreter(shebang)
	if err != nil {
		return nil, err
	}
	result, err := rpmCommand(ctx, interpreter, []string{"-I", "-c", rpmCaptureScript, repository, strconv.Itoa(unix.F_SETPIPE_SZ)}, bytes.NewReader(payload), 30*time.Minute)
	if err != nil {
		if stage, ok := strings.CutPrefix(result, "serverdeps-rpm-capture-stage:"); ok && RPMCaptureStageKnown(stage) {
			return nil, errors.New("serverdeps: RPM capture failed at " + stage + " (native diagnostics suppressed)")
		}
		return nil, err
	}
	captured := new(serverdepsv1.Manifest)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal([]byte(result), captured); err != nil {
		return nil, errors.New("serverdeps: native RHEL capture emitted an invalid manifest")
	}
	if !slices.Equal(input.GetRequestedPackages(), captured.GetRequestedPackages()) || captured.GetBaseImageSha256() != input.GetBaseImageSha256() || captured.GetMaxBytes() != input.GetMaxBytes() || captured.GetMaxPackages() != input.GetMaxPackages() || captured.GetCustody() != input.GetCustody() {
		return nil, errors.New("serverdeps: native RHEL capture changed admitted inputs")
	}
	root, err := openSnapshotRoot(repository)
	if err != nil {
		return nil, err
	}
	validation := ValidateRPM(ctx, root, captured)
	if err := errors.Join(validation, root.Close()); err != nil {
		return nil, err
	}
	return captured, nil
}

// ReplayRPM is the actual offline install consumer on a second fresh image
// baseline. It rejects a baseline mismatch and writes evidence only after the
// native transaction succeeded. External QEMU/VM fencing remains mandatory;
// InstallRPM also isolates the native transaction in an empty network namespace.
func ReplayRPM(ctx context.Context, repository string, captured *serverdepsv1.Manifest) (*serverdepsv1.Manifest, error) {
	baseline, err := rpmCommand(ctx, "rpm", []string{"-qa", "--queryformat", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"}, nil, time.Minute)
	if err != nil {
		return nil, err
	}
	packages := splitRPMPackages(baseline)
	if !slices.Equal(packages, captured.GetBasePackages()) {
		return nil, errors.New("serverdeps: offline RHEL replay is not the captured fresh image baseline")
	}
	vendorRootInventory, err := rpmCommand(ctx, "rpm", []string{"-q", "gpg-pubkey", "--queryformat", "%{NAME}-%{VERSION}-%{RELEASE}\n"}, nil, time.Minute)
	if err != nil {
		return nil, err
	}
	vendorRoots := splitRPMPackages(vendorRootInventory)
	if err := InstallRPM(ctx, repository, captured); err != nil {
		return nil, err
	}
	installed, err := rpmCommand(ctx, "rpm", []string{"-qa", "--queryformat", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"}, nil, time.Minute)
	if err != nil {
		return nil, err
	}
	actual := splitRPMPackages(installed)
	for _, item := range captured.GetFiles() {
		if item.GetKind() == serverdepsv1.FileKind_FILE_KIND_PACKAGE {
			if _, exists := slices.BinarySearch(actual, item.GetPackageIdentity()); !exists {
				return nil, errors.New("serverdeps: offline RHEL replay omitted a captured native RPM identity")
			}
		}
	}
	owner, err := rpmCommand(ctx, "rpm", []string{"-qf", "/usr/bin/rpm2cpio", "--queryformat", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}"}, nil, time.Minute)
	if err != nil {
		return nil, err
	}
	ownerCaptured := false
	for _, item := range captured.GetFiles() {
		if item.GetKind() == serverdepsv1.FileKind_FILE_KIND_PACKAGE && item.GetPackageIdentity() == owner && strings.HasPrefix(owner, "rpm-") {
			ownerCaptured = true
		}
	}
	if !ownerCaptured {
		return nil, errors.New("serverdeps: rpm2cpio utility is not owned by the captured vendor RPM package")
	}
	updated := proto.CloneOf(captured)
	updated.ManifestSha256 = ""
	updated.ReplayEvidencePath = "evidence/replay.json"
	evidence, err := json.Marshal(struct {
		ImageSHA256   string   `json:"base_image_sha256"`
		Baseline      []string `json:"fresh_baseline"`
		VendorRoots   []string `json:"pre_transaction_native_gpg_pubkeys"`
		Installed     []string `json:"installed_packages"`
		RPM2CPIOOwner string   `json:"rpm2cpio_native_owner"`
		SolverOffline bool     `json:"dnf_repositories_disabled"`
		Network       string   `json:"transaction_network"`
		Outcome       string   `json:"outcome"`
	}{captured.GetBaseImageSha256(), packages, vendorRoots, actual, owner, true, "empty-network-namespace", "native-transaction-and-exact-installed-identities-confirmed"})
	if err != nil {
		return nil, err
	}
	if err := writeRPMReplayEvidence(repository, evidence); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(evidence)
	updated.Files = append(updated.Files, &serverdepsv1.File{Path: updated.ReplayEvidencePath, Sha256: hex.EncodeToString(digest[:]), SizeBytes: uint64(len(evidence)), Kind: serverdepsv1.FileKind_FILE_KIND_EVIDENCE})
	updated.TotalBytes += uint64(len(evidence))
	if updated.TotalBytes > updated.MaxBytes {
		return nil, errors.New("serverdeps: replay evidence exceeds admitted closure bytes")
	}
	slices.SortFunc(updated.Files, func(a, b *serverdepsv1.File) int { return strings.Compare(a.Path, b.Path) })
	return updated, nil
}

func splitRPMPackages(output string) []string {
	lines := bytes.Split(bytes.TrimSpace([]byte(output)), []byte("\n"))
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if len(line) != 0 {
			result = append(result, string(line))
		}
	}
	slices.Sort(result)
	return result
}

func writeRPMReplayEvidence(repository string, evidence []byte) (err error) {
	root, err := openSnapshotRoot(repository)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	fd, err := unix.Openat2(int(root.Fd()), "evidence/replay.json", &unix.OpenHow{
		Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC,
		Mode:  0400, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "offline-replay-evidence")
	defer func() { err = errors.Join(err, file.Close()) }()
	if _, err := file.Write(evidence); err != nil {
		return err
	}
	return file.Sync()
}

// RPMCaptureStageKnown admits only fixed native acquisition stage names for
// the development guest adapter. No exception, argv, credential or URL is a
// diagnostic value. A stage name never establishes successful acquisition.
func RPMCaptureStageKnown(stage string) bool {
	switch stage {
	case "native-interpreter-import", "input-and-target", "baseline-query",
		"native-keyring-initialization", "vendor-key-acquisition", "vendor-key-import",
		"native-keyring-label", "native-keyring-diagnostic-initialization", "native-keyring-database-init",
		"native-keyring-database-init-permission-denied", "native-keyring-database-init-read-only",
		"native-keyring-database-init-locked", "native-keyring-database-init-backend", "native-keyring-database-init-timeout",
		"vendor-key-import-release2", "vendor-key-import-release4",
		"vendor-key-import-release2-permission-denied", "vendor-key-import-release4-permission-denied",
		"vendor-key-import-release2-read-only", "vendor-key-import-release4-read-only",
		"vendor-key-import-release2-locked", "vendor-key-import-release4-locked",
		"vendor-key-import-release2-backend", "vendor-key-import-release4-backend",
		"vendor-key-import-release2-timeout", "vendor-key-import-release4-timeout",
		"vendor-key-import-release2-unsupported-key-version", "vendor-key-import-release4-unsupported-key-version",
		"vendor-key-import-release2-unsupported-key-algorithm", "vendor-key-import-release4-unsupported-key-algorithm",
		"vendor-key-import-release2-key-policy-rejected", "vendor-key-import-release4-key-policy-rejected",
		"native-repository-configuration", "native-metadata-load", "native-dependency-solve",
		"metadata-retention", "native-package-download", "native-package-signature-check",
		"native-solver-version-query", "evidence-write", "manifest-output":
		return true
	default:
		return false
	}
}

// Credentials remain in RHSM's protected native files. Native diagnostics are
// discarded, configuration copies omit certificate/key paths, and only public
// repository URLs, package identities and acquisition decisions reach evidence.
const rpmCaptureScript = `import binascii, datetime, fcntl, hashlib, json, logging, os, pathlib, resource, shutil, subprocess, sys, tempfile, urllib.request, xml.etree.ElementTree as ET
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
logging.disable(sys.maxsize)
output = os.dup(1)
null = os.open(os.devnull, os.O_WRONLY)
os.dup2(null, 1)
os.dup2(null, 2)
os.close(null)
phase = 'native-interpreter-import'
def capture_failure(kind, value, traceback):
 os.write(output, ('serverdeps-rpm-capture-stage:' + phase).encode('ascii'))
sys.excepthook = capture_failure
import dnf, hawkey
phase = 'input-and-target'
m = json.load(sys.stdin)
root = pathlib.Path(sys.argv[1])
maximum = int(m['max_bytes'])
resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
maxpackages = int(m['max_packages'])
files = []
total = 0
keys = [
 ('567E347AD0044ADE55BA8A5F199E2F91FD431D51', 'fd431d51', 'd4b2543626bee31d9438d4a31731aae712c072893c7aed8854f16c42fafc742b'),
 ('FCD355B305707A62DA143AB6E422397E50FE8467A2A95343D246D6276AFEDF8F', '6afedf8f', '9052b2b274842f1b4f40f6e9f4d08691fb8be1ac2483027e12cca61ec68eab8b')]
class NoKeyRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self, req, fp, code, msg, headers, newurl):
  raise RuntimeError('vendor key redirect forbidden')
keyopener = urllib.request.build_opener(NoKeyRedirect())
def digest_file(p):
 h = hashlib.sha256()
 with open(p, 'rb') as f:
  for b in iter(lambda: f.read(1048576), b''): h.update(b)
 return h.hexdigest()
def record(name, kind, vendor='', metadata='', identity='', signer=''):
 global total
 p = root / name
 size = p.stat().st_size
 if size <= 0 or total + size > maximum or len(files) >= 5256: raise RuntimeError('closure bounds')
 sha = digest_file(p)
 if vendor and sha != vendor: raise RuntimeError('vendor checksum')
 total += size
 files.append(dict(path=name, sha256=sha, size_bytes=str(size), kind=kind, vendor_sha256=vendor, vendor_metadata_path=metadata, package_identity=identity, signer_fingerprint=signer))
 os.chmod(p, 0o400)
 return sha
def copy(source, name):
 p = root / name
 p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
 with open(source, 'rb') as src, open(p, 'xb') as dst:
  shutil.copyfileobj(src, dst, 1048576)
def command(args):
 with tempfile.TemporaryFile() as out:
  subprocess.run(args, stdout=out, stderr=subprocess.DEVNULL, check=True, timeout=60)
  if out.tell() > 1048576: raise RuntimeError('native output bound')
  out.seek(0)
  return out.read().decode('utf-8')
def keyring_command(args, stage):
 global phase
 phase = 'native-keyring-diagnostic-initialization'
 # Only fixed native keyring error markers may leave this 4 KiB anonymous pipe.
 # Neither raw diagnostics nor filesystem paths are persisted or returned.
 readfd, writefd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
 try:
  # Go supplies the Linux syscall command: Python 3.9 does not export F_SETPIPE_SZ.
  if fcntl.fcntl(writefd, int(sys.argv[2]), 4096) != 4096: raise RuntimeError('diagnostic pipe bound')
  phase = stage
  try:
   subprocess.run(args, stdout=subprocess.DEVNULL, stderr=writefd, check=True, timeout=60)
  except subprocess.TimeoutExpired:
   phase = stage + '-timeout'
   raise
  except subprocess.CalledProcessError:
   try: diagnostic = os.read(readfd, 4096).lower()
   except BlockingIOError: diagnostic = b''
   for marker, suffix in [(b'permission denied','permission-denied'), (b'read-only file system','read-only'), (b'database is locked','locked'), (b'unsupported database backend','backend'), (b'unknown database backend','backend')]:
    if marker in diagnostic:
     phase = stage + '-' + suffix
     break
   if phase == stage and stage.startswith('vendor-key-import-'):
    for marker, suffix in [(b'unsupported version of key','unsupported-key-version'), (b'unsupported key version','unsupported-key-version'), (b'unsupported public key algorithm','unsupported-key-algorithm'), (b'unsupported algorithm','unsupported-key-algorithm'), (b'policy rejects','key-policy-rejected')]:
     if marker in diagnostic:
      phase = stage + '-' + suffix
      break
   raise
 finally:
  os.close(readfd)
  os.close(writefd)
osrelease = {}
with open('/etc/os-release') as f:
 for line in f:
  if '=' in line:
   k,v = line.rstrip().split('=', 1)
   osrelease[k] = v.strip('"')
if osrelease.get('ID') != 'rhel' or not osrelease.get('VERSION_ID','').startswith('9.') or os.uname().machine != 'x86_64': raise RuntimeError('target')
if not pathlib.Path('/etc/pki/consumer/cert.pem').is_file(): raise RuntimeError('RHSM registration required')
phase = 'baseline-query'
baseline = sorted(command(['rpm','-qa','--queryformat','%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n']).strip().splitlines())
with tempfile.TemporaryDirectory(prefix='lindm-rhel-solve-') as work:
 phase = 'native-keyring-initialization'
 db = pathlib.Path(work) / 'rpmdb'
 db.mkdir(mode=0o700)
 if pathlib.Path('/sys/fs/selinux/enforce').is_file():
  phase = 'native-keyring-label'
  native_db = command(['rpm','--eval','%{_dbpath}']).strip()
  if native_db not in ['/var/lib/rpm','/usr/lib/sysimage/rpm']: raise RuntimeError('native database label reference')
  command(['chcon','--reference=/',work])
  command(['chcon','--reference=' + native_db,str(db)])
 phase = 'native-keyring-database-init'
 keyring_command(['/usr/bin/rpm','--dbpath',str(db),'--initdb'], 'native-keyring-database-init')
 for fingerprint, keyid, keysha in keys:
  phase = 'vendor-key-acquisition'
  name = 'keys/' + keyid + '.asc'
  p = root / name
  p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
  with keyopener.open('https://security.access.redhat.com/data/' + keyid + '.txt', timeout=60) as response:
   key = response.read(65537)
  if len(key) > 65536 or hashlib.sha256(key).hexdigest() != keysha: raise RuntimeError('vendor key pin')
  with open(p, 'xb') as f: f.write(key)
  record(name, 'FILE_KIND_KEY', signer=fingerprint)
  key_stage = 'vendor-key-import-release2' if keyid == 'fd431d51' else 'vendor-key-import-release4'
  keyring_command(['/usr/bin/rpmkeys','--dbpath',str(db),'--import',str(p)], key_stage)
 phase = 'native-repository-configuration'
 with dnf.Base() as base:
  base.conf.read()
  base.conf.cachedir = str(pathlib.Path(work) / 'cache')
  base.conf.persistdir = str(pathlib.Path(work) / 'persist')
  base.conf.logdir = str(pathlib.Path(work) / 'logs')
  base.conf.keepcache = True
  base.conf.zchunk = False
  base.conf.install_weak_deps = False
  base.conf.module_platform_id = 'platform:el9'
  base.conf.substitutions['releasever'] = '9'
  base.read_all_repos()
  sources = {'rhel-9-for-x86_64-baseos-rpms':'https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os', 'rhel-9-for-x86_64-appstream-rpms':'https://cdn.redhat.com/content/dist/rhel9/9/x86_64/appstream/os'}
  for repo in base.repos.values(): repo.disable()
  authentication = {}
  for id, source in sources.items():
   repo = base.repos[id]
   if list(repo.baseurl) != [source] or not repo.sslverify or not repo.gpgcheck or not repo.sslclientcert or not repo.sslclientkey or not repo.sslcacert or repo.metalink or repo.mirrorlist: raise RuntimeError('vendor TLS/RHSM repository configuration')
   for credential in [repo.sslclientcert, repo.sslclientkey, repo.sslcacert]:
    if not pathlib.Path(credential).is_file(): raise RuntimeError('vendor credential absent')
   authentication[id] = dict(tls_verify=bool(repo.sslverify), native_package_gpgcheck=bool(repo.gpgcheck), vendor_ca_sha256=digest_file(repo.sslcacert), rhsm_client_credentials_present=True)
   repo.skip_if_unavailable = False
   repo.enable()
  phase = 'native-metadata-load'
  base.fill_sack(load_system_repo=False)
  phase = 'native-dependency-solve'
  for requested in m['requested_packages']: base.install(requested, strict=True)
  base.resolve()
  packages = sorted(base.transaction.install_set, key=lambda p: str(p))
  if not packages or len(packages) > maxpackages or sum(p.downloadsize for p in packages) > maximum: raise RuntimeError('native closure bound')
  phase = 'metadata-retention'
  repositories = []
  primary = {}
  for id, source in sources.items():
   repo = base.repos[id]
   cache = pathlib.Path(repo._repo.getCachedir()) / 'repodata'
   indexname = 'metadata/' + id + '/repomd.xml'
   copy(cache / 'repomd.xml', indexname)
   record(indexname, 'FILE_KIND_METADATA')
   index = ET.parse(root / indexname).getroot()
   ns = {'r':'http://linux.duke.edu/metadata/repo'}
   for data in index.findall('r:data', ns):
    location = data.find('r:location', ns).attrib['href']
    if not location.startswith('repodata/') or pathlib.PurePosixPath(location).name != location[len('repodata/'):]: raise RuntimeError('metadata path')
    sourcefile = cache / pathlib.PurePosixPath(location).name
    if not sourcefile.is_file(): continue
    checksum = data.find('r:checksum', ns)
    if checksum.attrib.get('type') != 'sha256': raise RuntimeError('metadata checksum algorithm')
    name = 'metadata/' + id + '/' + sourcefile.name
    copy(sourcefile, name)
    record(name, 'FILE_KIND_METADATA', checksum.text.strip(), indexname)
    if data.attrib.get('type') == 'primary': primary[id] = name
   if id not in primary: raise RuntimeError('primary metadata missing')
   repositories.append(dict(id=id, source_url=source, authentication='vendor-tls-rhsm', metadata_path=indexname, signing_key_path='keys/fd431d51.asc', signer_fingerprint=keys[0][0]))
  if total + sum(p.downloadsize for p in packages) > maximum: raise RuntimeError('closure byte bound')
  phase = 'native-package-download'
  base.download_packages(packages)
  phase = 'native-package-signature-check'
  for p in packages:
   checksumtype, checksum = p.chksum
   if hawkey.chksum_name(checksumtype) != 'sha256': raise RuntimeError('package checksum algorithm')
   expected = binascii.hexlify(checksum).decode('ascii')
   identity = p.name + '-' + str(p.epoch) + ':' + p.version + '-' + p.release + '.' + p.arch
   if p.reponame not in sources or p.arch not in ['x86_64','noarch']: raise RuntimeError('package origin')
   name = 'packages/' + p.reponame + '/' + pathlib.Path(p.localPkg()).name
   copy(p.localPkg(), name)
   checked = command(['rpmkeys','--dbpath',str(db),'--checksig','--verbose',str(root/name)]).lower()
   signatures = [line for line in checked.splitlines() if 'signature' in line]
   signer = ''
   for fingerprint, keyid, keysha in keys:
    if signatures and all(line.rstrip().endswith(': ok') and ('key id ' + keyid in line or 'key id ' + fingerprint[-16:].lower() in line) for line in signatures): signer = fingerprint
   if not signer or 'not ok' in checked or 'nokey' in checked: raise RuntimeError('vendor signature')
   record(name, 'FILE_KIND_PACKAGE', expected, primary[p.reponame], identity, signer)
  phase = 'native-solver-version-query'
  solver = command(['rpm','-q','dnf','libdnf','libsolv','rpm','--queryformat','%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n']).strip()
  evidence = dict(native_solver=solver, requested_packages=m['requested_packages'], base_image_sha256=m['base_image_sha256'], baseline=baseline, load_system_repo=False, install_weak_deps=False, repositories=repositories, authentication=authentication, package_count=len(packages), acquisition='vendor TLS certificate verification and RHSM client authentication; vendor native package signatures', redistribution='private entitled customer use only; development-lab custody is not production content authorization')
  phase = 'evidence-write'
  name = 'evidence/capture.json'
  (root/name).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
  with open(root/name, 'x') as f: json.dump(evidence, f, sort_keys=True)
  record(name, 'FILE_KIND_EVIDENCE')
  m.update(base_packages=baseline, solver_version=solver, repositories=repositories, files=sorted(files,key=lambda f:f['path']), total_bytes=str(total), package_count=len(packages), capture_evidence_path=name, acquired_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), manifest_sha256='')
  m.pop('replay_evidence_path', None)
phase = 'manifest-output'
with os.fdopen(output, 'w') as f: json.dump(m, f, sort_keys=True)
`
