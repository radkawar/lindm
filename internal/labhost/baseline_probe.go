package labhost

// Python is part of the supported Ubuntu host base and is pinned by the
// transaction. These read-only probes never boot a guest or modify host policy.
const baselineProbe = `command -v python3 >/dev/null || { echo 'Ubuntu baseline requires its system python3; restore the distribution base installation first' >&2; exit 1; }
python3 - <<'LINDM_BASELINE_PROBE'
import grp, json, os, pwd, shlex, stat, subprocess

def command(*args):
    return subprocess.check_output(args, text=True).strip()

release = {}
with open('/etc/os-release', encoding='utf-8') as source:
    for line in source:
        if '=' in line:
            key, value = line.rstrip('\n').split('=', 1)
            fields = shlex.split(value)
            release[key] = fields[0] if fields else ''
if release.get('ID') != 'ubuntu' or release.get('VERSION_ID') != '24.04':
    raise RuntimeError('unsupported baseline host ' + release.get('PRETTY_NAME', 'unknown') + '; maintained pins support Ubuntu 24.04 amd64/arm64 only; add reviewed lab/baseline pins for another release')
architecture = command('dpkg', '--print-architecture')
account = pwd.getpwuid(os.getuid())
sources_path = '/etc/apt/sources.list.d/ubuntu.sources'
try:
    fd = os.open(sources_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r', encoding='utf-8') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 65536:
            raise RuntimeError('Ubuntu sources must be a root-owned bounded regular file, not group/other writable')
        ubuntu_sources = source.read(65537)
        if len(ubuntu_sources.encode('utf-8')) > 65536:
            raise RuntimeError('Ubuntu source configuration exceeds 64 KiB')
except OSError as error:
    raise RuntimeError('baseline requires the existing official Ubuntu deb822 source file at ' + sources_path + '; no repositories or keys were changed') from error
packages = {}
for line in command('dpkg-query', '-W', '-f=${binary:Package}\t${db:Status-Status}\t${Version}\n').splitlines():
    name, status, version = line.split('\t')
    # Keep foreign multiarch identities distinct, but make native package pins
    # match both Multi-Arch: same and ordinary packages.
    if name.endswith(':' + architecture):
        name = name[:-(len(architecture) + 1)]
    packages[name] = {'status': status, 'version': version}
kvm, kvm_error = False, ''
try:
    fd = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
    os.close(fd)
    kvm = True
except OSError as error:
    kvm_error = str(error)
groups = sorted(grp.getgrgid(group).gr_name for group in os.getgrouplist(account.pw_name, account.pw_gid))
session_groups = sorted(grp.getgrgid(group).gr_name for group in set(os.getgroups() + [os.getgid()]))
print(json.dumps({
    'distribution': release.get('ID', ''), 'release': release.get('VERSION_ID', ''),
    'description': release.get('PRETTY_NAME', ''), 'architecture': architecture,
    'user': account.pw_name, 'uid': os.getuid(), 'home': account.pw_dir,
    'cpus': int(command('nproc')), 'memory_mib': os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE') // (1024 * 1024),
    'groups': groups, 'session_groups': session_groups, 'kvm_open': kvm, 'kvm_error': kvm_error,
    'packages': packages, 'ubuntu_sources': ubuntu_sources,
}, sort_keys=True))
LINDM_BASELINE_PROBE
`

const baselineReadiness = `python3 - <<'LINDM_BASELINE_READY'
import hashlib, json, os, shutil, subprocess

def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()

# Exact package identity/version is checked again in Go against the pins.
# Record package-owned canonical paths and hashes, not guessed firmware paths.
firmware = []
for package, paths in {
    'qemu-efi-aarch64': [
        '/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd', '/usr/share/AAVMF/AAVMF_CODE.secboot.fd',
        '/usr/share/AAVMF/AAVMF_VARS.fd', '/usr/share/AAVMF/AAVMF_VARS.ms.fd'],
    'ovmf': [
        '/usr/share/OVMF/OVMF_CODE_4M.fd', '/usr/share/OVMF/OVMF_CODE_4M.secboot.fd',
        '/usr/share/OVMF/OVMF_VARS_4M.fd', '/usr/share/OVMF/OVMF_VARS_4M.ms.fd'],
}.items():
    owned = set(command('dpkg-query', '-L', '--', package).splitlines())
    version = command('dpkg-query', '-W', '-f=${Version}', '--', package)
    for path in paths:
        resolved = os.path.realpath(path)
        if path not in owned or resolved not in owned or not os.path.isfile(resolved):
            raise RuntimeError('firmware is not a regular file owned by ' + package + ': ' + path)
        digest = hashlib.sha256()
        with open(resolved, 'rb') as source:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
        firmware.append({'package': package, 'version': version, 'path': path, 'resolved_path': resolved, 'sha256': digest.hexdigest()})

# Tools without a stable version switch report their owning dpkg version. Every
# tool must resolve from the system PATH and belong to an installed package.
tools = {}
versions = {
    'qemu-system-aarch64': ['--version'], 'qemu-system-x86_64': ['--version'],
    'qemu-img': ['--version'], 'swtpm': ['--version'],
    'gpg': ['--version'], 'gpgv': ['--version'], 'gpgconf': ['--version'],
    'rsync': ['--version'], 'xorriso': ['-version'], 'guestfish': ['--version'],
    'virt-inspector': ['--version'], 'rpm': ['--version'], 'rpmbuild': ['--version'],
    'createrepo_c': ['--version'], 'gcc': ['--version'], 'go': ['version'],
    'ukify': ['--version'],
}
required = list(versions) + ['swtpm_setup', 'cloud-localds', 'virt-fw-vars', 'mcopy', 'mkfs.vfat', 'mkfs.ext4', 'cryptsetup',
    'unsquashfs', 'zstd', 'jq', 'ssh', 'scp', 'dpkg-deb', 'dpkg-scanpackages', 'debsigs', 'rpm2cpio',
    'rpmsign', 'rpmkeys', 'gpg-connect-agent', 'apt-ftparchive', 'systemd-analyze', 'gzip',
    'cpio', 'make', 'pkg-config', 'supermin', 'sbsign', 'cert-to-efi-sig-list', 'sign-efi-sig-list']
for name in required:
    path = shutil.which(name)
    if not path:
        raise RuntimeError('required native lane tool is missing: ' + name)
    resolved = os.path.realpath(path)
    # Ubuntu's merged-/usr symlinks can make the canonical path differ from
    # the spelling retained in dpkg's file list. Only accept the same inode.
    ownership = ''
    for candidate in dict.fromkeys([resolved, path, resolved[4:] if resolved.startswith('/usr/') else resolved]):
        if not os.path.exists(candidate) or not os.path.samefile(candidate, resolved):
            continue
        query = subprocess.run(['dpkg-query', '-S', '--', candidate], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if query.returncode == 0:
            ownership = query.stdout.strip()
            break
    if not ownership:
        raise RuntimeError('native tool is not package-owned: ' + resolved)
    owners = sorted(set(line.rsplit(': ', 1)[0] for line in ownership.splitlines()))
    package_versions = {owner: command('dpkg-query', '-W', '-f=${Version}', '--', owner) for owner in owners}
    version = command(path, *versions[name]) if name in versions else ''
    tools[name] = {'path': path, 'resolved_path': resolved, 'packages': package_versions, 'version_output': version}
print(json.dumps({'firmware': firmware, 'tools': tools}, sort_keys=True))
LINDM_BASELINE_READY
`
