# Fixed embedded DNF4 configuration probe, executed with python3 -I.
# API references: https://dnf.readthedocs.io/en/latest/api_base.html#dnf.Base.read_all_repos
# https://dnf.readthedocs.io/en/latest/api_conf.html
# This reads configuration only. It never initializes plugins, a sack, repository
# metadata, a transaction, RPM release detection, or any network operation.
import json
import os
import stat


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


def probe():
    try:
        import dnf
    except ModuleNotFoundError as error:
        if error.name == "dnf":
            return failed(2)
        raise
    if str(getattr(dnf, "__version__", "")).split(".")[0] != "4":
        return failed(2)
    reader = ConfigReader()
    with dnf.Base() as base:
        conf = base.conf
        # No plugin initialization is invoked, and native configuration cannot
        # re-enable plugins at lower priority than this explicit runtime value.
        conf.plugins = False
        reader.read(conf.config_file_path)
        conf.read()
        if conf.installroot != "/":
            return failed(2)
        varsdirs, reposdirs = list(conf.varsdir), list(conf.reposdir)
        if len(varsdirs) > 32 or len(reposdirs) > 32:
            return failed(6)
        for directory in varsdirs:
            reader.directory(directory)
        for directory in reposdirs:
            reader.directory(directory, ".repo")
        # The API owns variable precedence and parsing. Read only explicit lock
        # files in the effective configured order; never report detected OS
        # versions or subscription defaults as release locks.
        lock = observation(2)
        for directory in varsdirs:
            try:
                raw = reader.read(os.path.join(directory, "releasever"), 4096)
            except FileNotFoundError:
                continue
            value = raw.decode("utf-8")
            if value.endswith("\n"):
                value = value[:-1]
            if not value or any(ord(char) <= 32 or ord(char) == 127 for char in value):
                raise EvidenceFailure(5)
            lock = observation(1, value)
        conf.substitutions.update_from_etc("/", varsdir=varsdirs)
        base.read_all_repos()
        ids = []
        for repo in base.repos.iter_enabled():
            repoid = repo.id
            if not isinstance(repoid, str) or not repoid or len(repoid) > 256:
                raise EvidenceFailure(5)
            if "$" in repoid or any(ord(char) <= 32 or ord(char) == 127 for char in repoid):
                raise EvidenceFailure(5)
            if len(ids) == 256:
                raise EvidenceFailure(6)
            ids.append(repoid)
        if len(set(ids)) != len(ids):
            raise EvidenceFailure(5)
        return {
            "cpe": observation(2),
            "releaseverLock": lock,
            "repositories": {"status": 1, "ids": sorted(ids), "backend": "dnf4"},
        }


def main():
    try:
        result = probe()
    except EvidenceFailure as error:
        result = failed(error.status)
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
