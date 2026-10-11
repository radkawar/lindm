"""Private fixed helper, never a shell/native-command generator.

ABI: the packaged libalpm 16.0.1 public alpm.h/alpm_list.h. The Go caller
opens and validates the registry-pinned ELF and passes that descriptor as fd4.
Only fd3 carries the bounded readiness/permit protocol; package scripts cannot
inherit it. The native transaction lock survives preparation, signed authority,
commit, pin publication and the caller's post-effect database observation.
"""
import ctypes as C
import hashlib
import json
import os
import signal
import socket
import struct
import stat as filemode

LIMIT = 1 << 20
channel = socket.socket(fileno=3)
os.set_inheritable(3, False)
os.set_inheritable(4, False)
interrupted = False


def exact(n):
    if interrupted:
        raise RuntimeError("ALPM transaction interrupted")
    result = bytearray()
    while len(result) < n:
        chunk = channel.recv(n - len(result))
        if interrupted:
            raise RuntimeError("ALPM transaction interrupted")
        if not chunk:
            raise RuntimeError("ALPM authority channel closed")
        result.extend(chunk)
    return bytes(result)


def send(value):
    if interrupted:
        raise RuntimeError("ALPM transaction interrupted")
    data = json.dumps(value, separators=(",", ":")).encode()
    if len(data) > LIMIT:
        raise RuntimeError("ALPM response capacity")
    channel.sendall(struct.pack(">I", len(data)) + data)


def permit(value):
    if exact(1) != value:
        raise RuntimeError("ALPM authority protocol")


def stopped(_signal, _frame):
    # Never raise asynchronously: a signal delivered after trans_init returns
    # must not skip recording ownership, nor interrupt either cleanup call.
    # Closing the authority stream wakes a blocked read; exact/send report the
    # deferred cancellation at explicit protocol boundaries instead.
    global interrupted
    interrupted = True
    try:
        channel.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass # already closed; cancellation still forbids another permit


signal.signal(signal.SIGTERM, stopped)
size = struct.unpack(">I", exact(4))[0]
if size == 0 or size > LIMIT:
    raise RuntimeError("ALPM request capacity")
request = json.loads(exact(size))
alpm = C.CDLL("/proc/self/fd/4")


def function(name, result, *arguments):
    f = getattr(alpm, name)
    f.restype, f.argtypes = result, list(arguments)
    return f


pointer = C.c_void_p
text = C.c_char_p
integer = C.c_int
version = function("alpm_version", text)
if version().decode("ascii") != request["version"] or C.sizeof(pointer) != 8:
    raise RuntimeError("unsupported ALPM ABI")
initialize = function("alpm_initialize", pointer, text, text, C.POINTER(integer))
release = function("alpm_release", integer, pointer)
trans_init = function("alpm_trans_init", integer, pointer, integer)
trans_prepare = function("alpm_trans_prepare", integer, pointer, C.POINTER(pointer))
trans_commit = function("alpm_trans_commit", integer, pointer, C.POINTER(pointer))
trans_release = function("alpm_trans_release", integer, pointer)
trans_add = function("alpm_trans_get_add", pointer, pointer)
trans_remove = function("alpm_trans_get_remove", pointer, pointer)
load = function("alpm_pkg_load", integer, pointer, text, integer, integer, C.POINTER(pointer))
add = function("alpm_add_pkg", integer, pointer, pointer)
remove = function("alpm_remove_pkg", integer, pointer, pointer)
localdb = function("alpm_get_localdb", pointer, pointer)
find = function("alpm_db_get_pkg", pointer, pointer, text)
name = function("alpm_pkg_get_name", text, pointer)
arch = function("alpm_pkg_get_arch", text, pointer)
evr = function("alpm_pkg_get_version", text, pointer)
groups = function("alpm_pkg_get_groups", pointer, pointer)
compare = function("alpm_pkg_vercmp", integer, text, text)
set_gpg = function("alpm_option_set_gpgdir", integer, pointer, text)
set_log = function("alpm_option_set_logfile", integer, pointer, text)
add_arch = function("alpm_option_add_architecture", integer, pointer, text)
add_hook = function("alpm_option_add_hookdir", integer, pointer, text)
checkspace = function("alpm_option_set_checkspace", integer, pointer, integer)
libc = C.CDLL(None)
fnmatch = libc.fnmatch
fnmatch.restype, fnmatch.argtypes = integer, [text, text, integer]


# The only public struct read: alpm_list_t's three pointer fields, pinned above.
class Node(C.Structure):
    pass


Node._fields_ = [("data", pointer), ("prev", C.POINTER(Node)), ("next", C.POINTER(Node))]


def items(head):
    node, count = C.cast(head, C.POINTER(Node)), 0
    while node:
        count += 1
        if count > 8192:
            raise RuntimeError("ALPM selection capacity")
        yield node.contents.data
        node = node.contents.next


def identity(pkg):
    return [name(pkg).decode(), arch(pkg).decode(), evr(pkg).decode().removeprefix("0:")]


def held(pkg, removing):
    candidates = {"IgnorePkg": [name(pkg)], "IgnoreGroup": [C.cast(g, text).value for g in items(groups(pkg))]}
    if removing:
        candidates["HoldPkg"] = [name(pkg)]
    for key, values in request["holds"].items():
        for pattern in values:
            for candidate in candidates.get(key, []):
                if fnmatch(pattern.encode(), candidate, 0) == 0:
                    raise RuntimeError("externally held ALPM package or group")


def checked(value):
    if value != 0:
        raise RuntimeError("native ALPM transaction refused")


error = integer()
handle = initialize(b"/", b"/var/lib/pacman", C.byref(error))
if not handle:
    raise RuntimeError("native ALPM initialization refused")
locked = False
try:
    checked(set_gpg(handle, request["keyring"].encode()))
    checked(set_log(handle, request["log"].encode()))
    checked(add_arch(handle, request["architecture"].encode()))
    checked(add_hook(handle, b"/etc/pacman.d/hooks/"))
    checked(checkspace(handle, 1))
    if trans_init(handle, 0) != 0:  # no NOLOCK, NODEPS, NOHOOKS or NOSCRIPTLET
        raise RuntimeError("native ALPM lock acquisition refused")
    locked = True
    if interrupted:
        raise RuntimeError("ALPM transaction interrupted")
    lock = os.stat("/var/lib/pacman/db.lck", follow_symlinks=False)
    database = localdb(handle)
    expected_add, expected_remove = [], []
    seen = set()
    for entry in request["entries"]:
        if interrupted:
            raise RuntimeError("ALPM transaction interrupted")
        if entry["name"] in seen:
            raise RuntimeError("duplicate ALPM native name")
        seen.add(entry["name"])
        installed = find(database, entry["name"].encode())
        if installed and arch(installed).decode() != entry["architecture"]:
            raise RuntimeError("ALPM architecture replacement refused")
        before = evr(installed).decode().removeprefix("0:") if installed else ""
        if before != entry["before"]:
            raise RuntimeError("ALPM precondition changed under native lock")
        if entry["after"]:
            if installed and compare(entry["after"].encode(), evr(installed)) < 0:
                raise RuntimeError("ALPM downgrade refused")
            fd = os.open(entry["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as archive:
                stat = os.fstat(archive.fileno())
                if not filemode.S_ISREG(stat.st_mode) or stat.st_uid != 0 or stat.st_mode & 0o022 or stat.st_size != entry["size"]:
                    raise RuntimeError("ALPM archive custody changed")
                digest = hashlib.file_digest(archive, "sha256").hexdigest()
                after = os.fstat(archive.fileno())
                if digest != entry["sha256"] or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns):
                    raise RuntimeError("ALPM archive changed")
            pkg = pointer()
            checked(load(handle, entry["path"].encode(), 1, 1, C.byref(pkg)))  # ALPM_SIG_PACKAGE, no OPTIONAL/MARGINAL/UNKNOWN
            if identity(pkg) != [entry["name"], entry["architecture"], entry["after"]]:
                raise RuntimeError("ALPM signed archive identity mismatch")
            held(pkg, False)
            checked(add(handle, pkg))
            expected_add.append(identity(pkg))
        else:
            if not installed:
                raise RuntimeError("ALPM removal target missing")
            held(installed, True)
            checked(remove(handle, installed))
            expected_remove.append(identity(installed))
    diagnostics = pointer()
    checked(trans_prepare(handle, C.byref(diagnostics)))
    if sorted(identity(pkg) for pkg in items(trans_add(handle))) != sorted(expected_add) or sorted(identity(pkg) for pkg in items(trans_remove(handle))) != sorted(expected_remove):
        raise RuntimeError("ALPM solver introduced an unauthorized effect")
    send({"state": "ready", "device": lock.st_dev, "inode": lock.st_ino})
    authority = exact(1)
    if authority == b"A":
        send({"state": "aborted", "device": lock.st_dev, "inode": lock.st_ino})
    elif authority == b"C":
        if request["entries"]:
            checked(trans_commit(handle, C.byref(diagnostics)))
        send({"state": "committed", "device": lock.st_dev, "inode": lock.st_ino})
        permit(b"R")  # caller has published pin and checked database, still locked
    else:
        raise RuntimeError("ALPM authority protocol")
finally:
    try:
        try:
            if locked:
                checked(trans_release(handle))
        finally:
            checked(release(handle))
    finally:
        channel.close()
