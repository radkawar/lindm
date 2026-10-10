# Fixed embedded libdnf5 native-library binding; no policy-supplied Python, shell,
# options, plugins, package downloads, key imports, or transaction execution.
# API: https://dnf5.readthedocs.io/en/latest/tutorial/api-changes-from-dnf4.html
# The Go helper refreshes the approved authenticated repository first, then calls
# this adapter in native cache-only mode to resolve exact pre-download sizes.
import json
import os
import sys

import libdnf5.base
import libdnf5.repo
import libdnf5.transaction


def resolve(directory, operation, specification):
    if not os.path.isabs(directory) or operation not in ("install", "remove"):
        raise ValueError("invalid native resolver request")
    base = libdnf5.base.Base()
    config = base.get_config()
    # Deliberately do not load_config(): ambient drop-ins/hooks are not policy.
    config.plugins = False
    config.installroot = "/"
    config.reposdir = (os.path.join(directory, "repos"),)
    config.cachedir = os.path.join(directory, "cache")
    config.system_cachedir = os.path.join(directory, "cache")
    config.logdir = os.path.join(directory, "log")
    config.cacheonly = "all"
    config.install_weak_deps = False
    config.clean_requirements_on_remove = False
    config.skip_unavailable = False
    config.best = True
    config.pkg_gpgcheck = True
    config.repo_gpgcheck = True
    base.setup()
    repos = base.get_repo_sack()
    repos.create_repos_from_dir(os.path.join(directory, "repos"))
    repos.load_repos()
    goal = libdnf5.base.Goal(base)
    if operation == "install":
        goal.add_rpm_install(specification)
    else:
        goal.add_rpm_remove(specification)
    transaction = goal.resolve()
    if transaction.get_problems() != libdnf5.base.GoalProblem_NO_PROBLEM:
        raise ValueError("native dependency resolution failed")
    entries = []
    for item in transaction.get_transaction_packages():
        if len(entries) == 8192:
            raise ValueError("native transaction capacity")
        package = item.get_package()
        action = libdnf5.base.transaction.transaction_item_action_to_string(item.get_action())
        if action not in ("Install", "Upgrade", "Remove", "Replaced"):
            raise ValueError("unsafe native transaction action")
        entries.append({
            "nevra": package.get_full_nevra(),
            "action": action,
            "repo_id": package.get_repo_id(),
            "download_size": package.get_download_size() if action in ("Install", "Upgrade") else 0,
            "file_name": os.path.basename(package.get_location()) if action in ("Install", "Upgrade") else "",
        })
    return {"version": 1, "entries": entries}


try:
    if len(sys.argv) != 4:
        raise ValueError("invalid native resolver arguments")
    result = resolve(sys.argv[1], sys.argv[2], sys.argv[3])
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
except Exception as error:
    # Native exception text can contain repository endpoints. Preserve failure,
    # not sensitive detail, and never emit a successful empty transaction.
    print("native_libdnf5_resolver_failed:" + type(error).__name__, file=sys.stderr)
    sys.exit(1)
