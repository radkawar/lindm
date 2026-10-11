# Fixed embedded DNF4 (dnf 4.x Python API) package transaction adapter; no
# policy-supplied Python, shell, options or ambient plugins. API reference:
# https://dnf.readthedocs.io/en/latest/api_base.html
# The Go provider runs it with the native DNF interpreter (python -I) in
# separately bounded phases mirroring DNF5 store/replay:
#   probe                   native versionlock effectiveness, no repositories
#   resolve DIR OP SPEC VL  refresh the approved repository, declare exact sizes
#   stage DIR OP SPEC VL    cache-only re-resolution, download, transaction.json
#   check DIR VL            cache-only replay resolution of the staged bundle
#   apply DIR VL            check, signature verification, native transaction
# The approved repository and its signing key are provider-written under DIR.
# VL=1 loads only the native versionlock plugin; no other plugin ever runs.
# Staging has a read-only host, so it resolves against a private consistent
# snapshot of the native history database (inherited install reasons).
import json
import logging
import os
import sqlite3
import sys

import rpm

# RPM must verify every package signature and digest during the transaction,
# not merely when DNF chooses to; set before DNF creates its transaction set.
rpm.addMacro("_pkgverify_level", "all")

import dnf  # noqa: E402
import dnf.exceptions  # noqa: E402
import dnf.yum.rpmtrans  # noqa: E402
import libdnf.transaction  # noqa: E402

VERSIONLOCK_LIST = "/etc/dnf/plugins/versionlock.list"
NATIVE_HISTORY = "/var/lib/dnf/history.sqlite"
MAX_ENTRIES = 8192

ACTIONS = {
    libdnf.transaction.TransactionItemAction_INSTALL: "Install",
    libdnf.transaction.TransactionItemAction_UPGRADE: "Upgrade",
    libdnf.transaction.TransactionItemAction_UPGRADED: "Replaced",
    libdnf.transaction.TransactionItemAction_REMOVE: "Remove",
}
REASONS = {
    libdnf.transaction.TransactionItemReason_USER: "User",
    libdnf.transaction.TransactionItemReason_DEPENDENCY: "Dependency",
    libdnf.transaction.TransactionItemReason_WEAK_DEPENDENCY: "Weak Dependency",
}


class Failure(Exception):
    pass


def quiet():
    # Native diagnostics can contain repository endpoints; never echo them.
    for name in ("dnf", "dnf.plugin", "dnf.rpm", "librepo"):
        logger = logging.getLogger(name)
        logger.addHandler(logging.NullHandler())
        logger.propagate = False


def nevra(pkg):
    return "%s-%d:%s-%s.%s" % (pkg.name, pkg.epoch, pkg.version, pkg.release, pkg.arch)


def versionlock_plugin(base):
    loaded = [plugin for plugin in base._plugins.plugins if plugin.name == "versionlock"]
    return loaded[0] if len(loaded) == 1 else None


def history_snapshot(directory, name):
    # Preparation phases share one snapshot; the pre-effect check takes its own
    # fresh snapshot so inherited reasons are current at authorization time.
    persist = os.path.join(directory, name)
    target = os.path.join(persist, "history.sqlite")
    if name == "persist" and os.path.exists(target):
        return persist
    os.makedirs(persist, mode=0o700, exist_ok=True)
    if os.path.exists(target):
        os.remove(target)
    if not os.path.exists(NATIVE_HISTORY):
        return persist  # A system without DNF history has no inherited reasons.
    source = sqlite3.connect("file:" + NATIVE_HISTORY + "?mode=ro", uri=True)
    try:
        copy = sqlite3.connect(target)
        try:
            if hasattr(source, "backup"):
                source.backup(copy)
            else:
                # EL8 platform-python 3.6 predates the online backup API; one
                # explicit read transaction still yields a consistent dump.
                source.execute("BEGIN")
                try:
                    dump = "\n".join(source.iterdump())
                finally:
                    source.rollback()
                copy.executescript(dump)
        finally:
            copy.close()
    finally:
        source.close()
    return persist


def make_base(directory, cacheonly, versionlock, snapshot):
    base = dnf.Base()
    conf = base.conf
    # Deliberately do not read ambient dnf.conf, drop-ins or repositories.
    conf.installroot = "/"
    conf.config_file_path = os.path.join(directory, "dnf.conf")
    conf.reposdir = [os.path.join(directory, "repos")]
    conf.cachedir = os.path.join(directory, "cache")
    conf.logdir = os.path.join(directory, "log")
    if snapshot:
        conf.persistdir = history_snapshot(directory, snapshot)
    conf.varsdir = []
    conf.cacheonly = cacheonly
    conf.install_weak_deps = False
    conf.clean_requirements_on_remove = False
    conf.keepcache = True
    conf.skip_if_unavailable = False
    conf.best = True
    conf.strict = True
    conf.gpgcheck = True
    conf.repo_gpgcheck = True
    conf.localpkg_gpgcheck = True
    conf.tsflags = []
    conf.assumeyes = True
    conf.plugins = versionlock
    if versionlock:
        base.init_plugins(disabled_glob=["*"], enable_plugins=["versionlock"])
        plugin = versionlock_plugin(base)
        base.pre_configure_plugins()
        base.configure_plugins()
        if plugin is None or not plugin.locking_enabled():
            raise Failure("versionlock_unavailable")
        if sys.modules[type(plugin).__module__].locklist_fn != VERSIONLOCK_LIST:
            raise Failure("versionlock_locklist")
    base.read_all_repos()
    return base


def probe():
    # Native effectiveness: global plugins on, plugin installed and enabled in
    # its own configuration, and the fixed list present. Read-only.
    base = dnf.Base()
    base.conf.read()
    result = {"version": dnf.const.VERSION, "versionlock": ""}
    if base.conf.plugins:
        base.init_plugins(disabled_glob=["*"], enable_plugins=["versionlock"])
        plugin = versionlock_plugin(base)
        if plugin is not None:
            parser = type(plugin).read_config(base.conf)
            disabled = parser.has_section("main") and parser.has_option("main", "enabled") and not parser.getboolean("main", "enabled")
            plugin.config()
            locklist = sys.modules[type(plugin).__module__].locklist_fn
            if not disabled and locklist == VERSIONLOCK_LIST and os.path.isfile(VERSIONLOCK_LIST):
                result["versionlock"] = locklist
    return result


def transaction_entries(base):
    entries = []
    for item in base.transaction:
        if len(entries) == MAX_ENTRIES:
            raise Failure("transaction_capacity")
        action = ACTIONS.get(item.action)
        if action is None:
            # Downgrade, reinstall, obsoletes and reason changes are refused.
            raise Failure("unsafe_action")
        pkg = item.pkg
        entries.append({
            "nevra": nevra(pkg),
            "action": action,
            "reason": REASONS.get(item.reason, "Unknown"),
            "repo_id": pkg.reponame,
            "pkg": pkg,
        })
    return entries


def resolve_request(base, operation, specification):
    if operation == "install":
        base.install(specification, strict=True)
    elif operation == "remove":
        try:
            base.remove(specification)
        except dnf.exceptions.PackagesNotInstalledError:
            return []  # Already absent; the Go provider re-verifies the database.
    else:
        raise Failure("operation")
    # Never erase other packages to satisfy the request.
    base.resolve(allow_erasing=False)
    return transaction_entries(base)


def resolve(directory, operation, specification, versionlock):
    base = make_base(directory, False, versionlock, "persist")
    try:
        for repo in base.repos.iter_enabled():
            repo.metadata_expire = 0
        base.fill_sack(load_system_repo=True, load_available_repos=True)
        declared = []
        for entry in resolve_request(base, operation, specification):
            inbound = entry["action"] in ("Install", "Upgrade")
            declared.append({
                "nevra": entry["nevra"],
                "action": entry["action"],
                "repo_id": entry["repo_id"],
                "download_size": entry["pkg"].downloadsize if inbound else 0,
                "file_name": os.path.basename(entry["pkg"].location) if inbound else "",
            })
        return {"version": 1, "entries": declared}
    finally:
        base.close()


def stage(directory, operation, specification, versionlock):
    store = os.path.join(directory, "transaction")
    packages = os.path.join(store, "packages")
    os.makedirs(packages, mode=0o700)
    # Package downloads are refused under cacheonly; the already refreshed
    # metadata must not expire instead, so resolution cannot silently change.
    base = make_base(directory, False, versionlock, "persist")
    try:
        base.conf.check_config_file_age = False
        for repo in base.repos.iter_enabled():
            repo.metadata_expire = -1
            repo.pkgdir = packages
        base.fill_sack(load_system_repo=True, load_available_repos=True)
        entries = resolve_request(base, operation, specification)
        inbound = [entry["pkg"] for entry in entries if entry["action"] in ("Install", "Upgrade")]
        if inbound:
            base.download_packages(inbound)
        rpms = []
        for entry in entries:
            record = {"nevra": entry["nevra"], "action": entry["action"], "reason": entry["reason"], "repo_id": entry["repo_id"]}
            if entry["action"] in ("Install", "Upgrade"):
                local = entry["pkg"].localPkg()
                if os.path.dirname(local) != packages:
                    raise Failure("package_location")
                code, _ = base.package_signature_check(entry["pkg"])
                if code != 0:
                    raise Failure("signature")
                record["package_path"] = "packages/" + os.path.basename(local)
            rpms.append(record)
        if not rpms:
            return  # DNF stores no bundle for an already satisfied request.
        document = json.dumps({"version": "1.0", "rpms": rpms}, ensure_ascii=True, separators=(",", ":"))
        temporary = os.path.join(store, ".transaction.json")
        with open(temporary, "x") as output:
            output.write(document)
            output.flush()
            os.fsync(output.fileno())
        os.rename(temporary, os.path.join(store, "transaction.json"))
    finally:
        base.close()


def staged(directory):
    store = os.path.join(directory, "transaction")
    with open(os.path.join(store, "transaction.json")) as source:
        document = json.load(source)
    if document.get("version") != "1.0" or len(document.get("rpms", [])) > MAX_ENTRIES:
        raise Failure("staged_shape")
    return store, document["rpms"]


def replay(base, directory):
    store, rpms = staged(directory)
    paths = [os.path.join(store, item["package_path"]) for item in rpms if item["action"] in ("Install", "Upgrade")]
    base.fill_sack(load_system_repo=True, load_available_repos=False)
    local = {nevra(pkg): pkg for pkg in base.add_remote_rpms(paths, strict=True)} if paths else {}
    if len(local) != len(paths):
        raise Failure("staged_packages")
    for item in rpms:
        if item["reason"] != "User":
            continue  # Dependencies are selected by the solver, as staged.
        if item["action"] == "Install":
            base.package_install(local[item["nevra"]], strict=True)
        elif item["action"] == "Upgrade":
            base.package_upgrade(local[item["nevra"]])
        elif item["action"] == "Remove":
            installed = base.sack.query().installed().filter(nevra_strict=item["nevra"]).run()
            if len(installed) != 1:
                raise Failure("staged_removal")
            base.package_remove(installed[0])
    base.resolve(allow_erasing=False)
    entries = transaction_entries(base)
    want = sorted((item["nevra"], item["action"], item["reason"]) for item in rpms)
    have = sorted((entry["nevra"], entry["action"], entry["reason"]) for entry in entries)
    if want != have:
        raise Failure("replay_mismatch")
    for entry in entries:
        if entry["action"] in ("Install", "Upgrade"):
            if entry["repo_id"] != "@commandline":
                raise Failure("replay_source")
            code, _ = base.package_signature_check(entry["pkg"])
            if code != 0:
                raise Failure("signature")


class Display(dnf.yum.rpmtrans.TransactionDisplay):
    def __init__(self):
        super().__init__()
        self.failed = False

    def error(self, message):
        # Scriptlet and per-element failures leave a native outcome that only
        # independent database observation may classify.
        self.failed = True


def check(directory, versionlock):
    base = make_base(directory, True, versionlock, "persist-check")
    try:
        replay(base, directory)
    finally:
        base.close()


def apply(directory, versionlock):
    base = make_base(directory, True, versionlock, None)
    try:
        replay(base, directory)
        display = Display()
        base.do_transaction(display=[display])
        if display.failed:
            raise Failure("native_transaction_element")
    finally:
        base.close()


def main(arguments):
    quiet()
    if arguments == ["probe"]:
        return probe()
    if len(arguments) < 3 or arguments[-1] not in ("0", "1"):
        raise Failure("arguments")
    mode, directory, versionlock = arguments[0], arguments[1], arguments[-1] == "1"
    if not os.path.isabs(directory):
        raise Failure("directory")
    if mode == "resolve" and len(arguments) == 5:
        return resolve(directory, arguments[2], arguments[3], versionlock)
    if mode == "stage" and len(arguments) == 5:
        stage(directory, arguments[2], arguments[3], versionlock)
        return None
    if mode == "check" and len(arguments) == 3:
        check(directory, versionlock)
        return None
    if mode == "apply" and len(arguments) == 3:
        apply(directory, versionlock)
        return None
    raise Failure("arguments")


try:
    result = main(sys.argv[1:])
    if result is not None:
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
except Exception as error:
    reason = str(error) if isinstance(error, Failure) else type(error).__name__
    print("native_dnf4_failed:" + reason, file=sys.stderr)
    sys.exit(1)
