# Embedded by scaleout.go; executed only over authenticated SSH on Linux.
# A private directory, startup lock and pidfd bind cleanup to this exact run.
import base64
import fcntl
import hashlib
import json
import os
import pathlib
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

operation, directory, token = sys.argv[1:4]
root = pathlib.Path(directory)
if root.parent != pathlib.Path('/tmp') or root.name != 'lindm-scaleout-' + token:
    raise RuntimeError('invalid owned directory')
os.umask(0o077)


def owned():
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('remote directory custody changed')
    if (root / 'owner').read_text() != token:
        raise RuntimeError('remote owner changed')


def process_state(pid):
    text = pathlib.Path('/proc/%d/stat' % pid).read_text()
    return text[text.index('(') + 1:text.rindex(')')], text.rsplit(')', 1)[1].split()


# lindmd makes itself non-dumpable, so /proc/PID/exe is unreadable to this user
# after startup. PID plus start time is unique; the command name and real UID
# reject an unrelated process that reused the PID.
def identity(state):
    name, fields = process_state(state['pid'])
    uid = next(line.split()[1] for line in pathlib.Path('/proc/%d/status' % state['pid']).read_text().splitlines() if line.startswith('Uid:'))
    if fields[19] != state['start'] or name != 'lindmd' or int(uid) != os.getuid():
        raise RuntimeError('remote process identity changed')
    return fields


if operation == 'prepare':
    if sys.version_info < (3, 11) or not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise RuntimeError('scale-out requires Python 3.11+ and Linux pidfds')
    payload = json.load(sys.stdin)
    root.mkdir(mode=0o700)
    (root / 'owner').write_text(token)
    for name, data in payload['files'].items():
        if pathlib.Path(name).name != name or name in ('owner', 'lindmd', 'lock', 'aborted', 'state.json', 'server.log'):
            raise RuntimeError('invalid staged filename')
        with (root / name).open('xb') as output:
            output.write(base64.b64decode(data, validate=True))
    shutil.copyfile(payload['binary'], root / 'lindmd')
    os.chmod(root / 'lindmd', 0o700)
    with (root / 'lindmd').open('rb') as binary:
        digest = hashlib.file_digest(binary, 'sha256').hexdigest()
    if digest != payload['digest']:
        raise RuntimeError('replica binary differs from local binary')
    cfg = json.loads((root / 'server.json').read_text())
    reservations = []
    for key in ('adminListener', 'deviceListener', 'profiling'):
        if key not in cfg:
            continue
        listener = cfg[key]['listener'] if key == 'profiling' else cfg[key]
        sock = socket.socket()
        sock.bind((listener['address'], 0))
        listener['port'] = sock.getsockname()[1]
        reservations.append(sock)
    (root / 'server.json').write_text(json.dumps(cfg))
    print(json.dumps({'admin': cfg['adminListener']['port'], 'device': cfg['deviceListener']['port']}))
elif operation == 'run':
    owned()
    child = None
    stopping = False

    def stop(signum, frame):
        global stopping
        stopping = True

    for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    try:
        with (root / 'lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if (root / 'aborted').exists():
                raise RuntimeError('startup was cancelled')
            args = [str(root / 'lindmd'), 'serve', '-config', str(root / 'server.json')]
            if sys.argv[4]:
                args = ['taskset', '--cpu-list', sys.argv[4]] + args
            with (root / 'server.log').open('ab') as log:
                child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
            # Publish custody only after taskset has execed the owned binary.
            deadline = time.monotonic() + 5
            while process_state(child.pid)[0] != 'lindmd':
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('owned replica did not exec')
                time.sleep(0.01)
            state = {'pid': child.pid, 'start': process_state(child.pid)[1][19]}
            temporary = root / 'state.pending'
            temporary.write_text(json.dumps(state))
            temporary.rename(root / 'state.json')
        while not stopping and child.poll() is None:
            readable, _, _ = select.select([sys.stdin], [], [], 0.2)
            if readable and not os.read(sys.stdin.fileno(), 1):
                break
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=40)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
elif operation == 'cleanup':
    if not root.exists():
        sys.exit(0)
    # Cancellation between mkdir and writing the owner marker can leave only
    # an empty directory. rmdir never crosses into or deletes foreign content.
    if not (root / 'owner').exists():
        info = root.lstat()
        if stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700:
            root.rmdir()
            sys.exit(0)
    owned()
    with (root / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        (root / 'aborted').touch()
        if (root / 'state.json').exists():
            state = json.loads((root / 'state.json').read_text())
            try:
                descriptor = os.pidfd_open(state['pid'])
            except ProcessLookupError:
                descriptor = None
            if descriptor is not None:
                try:
                    if not select.select([descriptor], [], [], 0)[0]:
                        identity(state)
                        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                        if not select.select([descriptor], [], [], 40)[0]:
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                            if not select.select([descriptor], [], [], 5)[0]:
                                raise RuntimeError('remote process did not exit; retaining custody')
                finally:
                    os.close(descriptor)
        shutil.rmtree(root)
elif operation == 'sample':
    owned()
    state = json.loads((root / 'state.json').read_text())
    fields = identity(state)
    effective = ''
    for line in pathlib.Path('/proc/%d/status' % state['pid']).read_text().splitlines():
        if line.startswith('Cpus_allowed_list:'):
            effective = line.split(':', 1)[1].strip()
    print(json.dumps({'pid': state['pid'], 'cpu_clock_ticks': int(fields[11]) + int(fields[12]),
                      'rss_bytes': int(fields[21]) * os.sysconf('SC_PAGE_SIZE'), 'effective_cpus': effective}))
else:
    raise RuntimeError('unknown remote operation')
