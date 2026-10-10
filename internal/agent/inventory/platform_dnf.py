# Fixed embedded DNF4/libdnf5 configuration probe, executed with python3 -I.
# Supported APIs: dnf.readthedocs.io/en/latest/api_base.html and
# dnf5.readthedocs.io/en/latest/api/python/python.html.
# Reads native configuration and RPM release detection only; no plugins,
# repository metadata loading, transactions, downloads or network operations.
import json
import os
import stat
import sys
from urllib.parse import urlsplit, urlunsplit


class EvidenceFailure(Exception):
    def __init__(self, status):
        self.status = status


def observation(status, value=None):
    result = {"status": status}
    if value is not None:
        result["value"] = value
    return result


def failed(status):
    return {
        "cpe": observation(2),
        "releaseverLock": observation(status),
        "releasever": observation(status),
        "repositories": {"status": status},
    }


class ConfigReader:
    def __init__(self):
        self.total = 0
        self.files = 0

    def read(self, path, limit=65536):
        if not os.path.isabs(path):
            raise EvidenceFailure(5)
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise EvidenceFailure(5)
            data = source.read(limit + 1)
        self.files += 1
        self.total += len(data)
        if len(data) > limit or self.files > 1024 or self.total > 4 * 1024 * 1024:
            raise EvidenceFailure(6)
        return data

    def directory(self, path, suffix=None):
        if not os.path.isabs(path):
            raise EvidenceFailure(5)
        try:
            entries = os.scandir(path)
        except FileNotFoundError:
            return
        with entries:
            count = 0
            for entry in entries:
                count += 1
                if count > 256:
                    raise EvidenceFailure(6)
                if suffix is not None and not entry.name.endswith(suffix):
                    continue
                # Native DNF ignores subdirectories in varsdir; no recursive
                # traversal or arbitrary per-user environment is involved.
                if entry.is_dir():
                    continue
                self.read(entry.path)


def checked_directories(reader, varsdirs, reposdirs):
    if len(varsdirs) > 32 or len(reposdirs) > 32:
        raise EvidenceFailure(6)
    for directory in varsdirs:
        reader.directory(directory)
    for directory in reposdirs:
        reader.directory(directory, ".repo")
    # Effective native variable precedence; only explicit files are locks.
    lock = observation(2)
    for directory in varsdirs:
        try:
            raw = reader.read(os.path.join(directory, "releasever"), 4096)
        except FileNotFoundError:
            continue
        value = raw.decode("utf-8").removesuffix("\n")
        if not value or any(ord(char) <= 32 or ord(char) == 127 for char in value):
            raise EvidenceFailure(5)
        lock = observation(1, value)
    return lock


def repository(repoid, baseurls, metalink, mirrorlist, gpgcheck, keys):
    if not isinstance(repoid, str) or not repoid or len(repoid) > 256:
        raise EvidenceFailure(5)
    if "$" in repoid or any(ord(char) <= 32 or ord(char) == 127 for char in repoid):
        raise EvidenceFailure(5)
    redacted = False

    def safe_url(value):
        nonlocal redacted
        if not value:
            return ""
        if len(value) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise EvidenceFailure(5)
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https", "file", "ftp"):
            raise EvidenceFailure(5)
        # Userinfo, query strings and fragments can all contain credentials.
        # Never guess which query parameter names are secret.
        authority = parsed.netloc.rsplit("@", 1)[-1]
        safe = urlunsplit((parsed.scheme, authority, parsed.path, "", ""))
        redacted = redacted or safe != value
        return safe

    if len(baseurls) > 32 or len(keys) > 32:
        raise EvidenceFailure(6)
    result = {
        "id": repoid,
        "baseUrls": [safe_url(url) for url in baseurls],
        "metalink": safe_url(metalink),
        "mirrorlist": safe_url(mirrorlist),
        "gpgcheck": bool(gpgcheck),
        "gpgKeys": [safe_url(url) for url in keys],
    }
    result["urlsRedacted"] = redacted
    return result


def result(lock, releasever, repositories, backend):
    repositories.sort(key=lambda repo: repo["id"])
    ids = [repo["id"] for repo in repositories]
    if len(ids) > 256:
        raise EvidenceFailure(6)
    if len(set(ids)) != len(ids):
        raise EvidenceFailure(5)
    return {
        "cpe": observation(2),
        "releaseverLock": lock,
        "releasever": observation(1, releasever) if releasever else observation(2),
        "repositories": {"status": 1, "ids": ids, "backend": backend,
                         "configurations": repositories},
    }


def probe4():
    import dnf
    import dnf.rpm
    if str(getattr(dnf, "__version__", "")).split(".")[0] != "4":
        return failed(2)
    reader = ConfigReader()
    with dnf.Base() as base:
        conf = base.conf
        conf.plugins = False
        reader.read(conf.config_file_path)
        conf.read()
        if conf.installroot != "/":
            return failed(2)
        varsdirs, reposdirs = list(conf.varsdir), list(conf.reposdir)
        lock = checked_directories(reader, varsdirs, reposdirs)
        releasever = dnf.rpm.detect_releasever("/")
        if releasever is not None:
            conf.substitutions["releasever"] = releasever
        conf.substitutions.update_from_etc("/", varsdir=varsdirs)
        base.read_all_repos()
        repositories = []
        for repo in base.repos.iter_enabled():
            if len(repositories) == 256:
                raise EvidenceFailure(6)
            repositories.append(repository(repo.id, list(repo.baseurl), repo.metalink or "",
                                           repo.mirrorlist or "", repo.gpgcheck, list(repo.gpgkey)))
        return result(lock, conf.substitutions.get("releasever", ""), repositories, "dnf4")


def probe5():
    import libdnf5
    reader = ConfigReader()
    base = libdnf5.base.Base()
    conf = base.get_config()
    conf.plugins = False
    # These are libdnf5's supported system drop-in locations. Bound their input
    # before asking the native parser to process it, including repo overrides.
    for directory in ("/etc/dnf/libdnf5.conf.d", "/usr/share/dnf5/libdnf.conf.d"):
        reader.directory(directory, ".conf")
    try:
        reader.read(conf.config_file_path)
    except FileNotFoundError:
        pass  # libdnf5 supports missing main configuration with defaults.
    base.load_config()
    if conf.installroot != "/":
        return failed(2)
    lock = checked_directories(reader, list(conf.varsdir), list(conf.reposdir))
    for directory in ("/etc/dnf/repos.override.d", "/usr/share/dnf5/repos.override.d"):
        reader.directory(directory, ".repo")
    base.setup()
    base.get_repo_sack().create_repos_from_system_configuration()
    query = libdnf5.repo.RepoQuery(base)
    query.filter_enabled(True)
    repositories = []
    for repo in query:
        if len(repositories) == 256:
            raise EvidenceFailure(6)
        config = repo.get_config()
        metalink = config.get_metalink_option()
        mirrorlist = config.get_mirrorlist_option()
        repositories.append(repository(
            repo.get_id(), list(config.baseurl),
            "" if metalink.empty() else metalink.get_value(),
            "" if mirrorlist.empty() else mirrorlist.get_value(),
            config.get_pkg_gpgcheck_option().get_value(), list(config.gpgkey)))
    variables = base.get_vars()
    releasever = variables.get_value("releasever") if variables.contains("releasever") else ""
    return result(lock, releasever, repositories, "dnf5")


def probe():
    if sys.argv[1:] == ["dnf5"]:
        return probe5()
    if sys.argv[1:] == ["dnf4"]:
        return probe4()
    raise EvidenceFailure(5)


def main():
    try:
        result = probe()
    except EvidenceFailure as error:
        result = failed(error.status)
    except ModuleNotFoundError as error:
        result = failed(2 if error.name in ("dnf", "libdnf5") else 7)
    except PermissionError:
        result = failed(3)
    except FileNotFoundError:
        result = failed(2)
    except (UnicodeError, ValueError):
        result = failed(5)
    except Exception:
        # Do not expose native exception text: repository configuration may
        # contain credentials, URLs, or private paths. Only status leaves here.
        result = failed(7)
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
