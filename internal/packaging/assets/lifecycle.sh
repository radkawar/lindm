#!/bin/sh
# Fixed package lifecycle for lindm-agent. Verbs are closed. This is not a
# shell provider: it does not evaluate package-manager data, and it never
# deletes the lindm account, the executor journal, or the observation spool.
# GNU coreutils stat is required on the supported Debian and RPM images.
set -eu
cd / || {
	printf 'lindm-agent: cannot change to /\n' >&2
	exit 1
}
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 022

ACCOUNT=lindm
PARENT=/var/lib/lindm
EXECUTOR=/var/lib/lindm/executor
AGENT=/var/lib/lindm/agent
BINARY=/usr/libexec/lindm/lindm-agent
SYSUSERS=/usr/lib/sysusers.d/lindm.conf
TMPFILES=/usr/lib/tmpfiles.d/lindm.conf
EXECUTOR_UNIT=lindm-executor.service
AGENT_UNIT=lindm-agent.service
FIREWALL_RESTORE_UNIT=lindm-firewall-restore.service
CONNECTIVITY_GUARD_UNIT=lindm-connectivity-guard.service
SESSION_USER_UNIT=lindm-session.service

fail() {
	printf 'lindm-agent: %s\n' "$1" >&2
	exit 1
}

reject_symlink() {
	if [ -L "$1" ]; then
		fail "$1 is a symlink; refusing to follow or replace protected state"
	fi
}

systemd_running() {
	[ -d /run/systemd/system ]
}

ensure_account() {
	if getent passwd "$ACCOUNT" >/dev/null 2>&1; then
		uid=$(id -u "$ACCOUNT")
		if [ "$uid" -eq 0 ]; then
			fail "account lindm resolved to UID 0"
		fi
		return 0
	fi
	if [ ! -x /usr/bin/systemd-sysusers ] && [ ! -x /bin/systemd-sysusers ]; then
		fail "systemd-sysusers is required; refusing to invent a UID"
	fi
	systemd-sysusers "$SYSUSERS" || fail "systemd-sysusers failed"
	if ! getent passwd "$ACCOUNT" >/dev/null 2>&1; then
		fail "account lindm was not created"
	fi
	uid=$(id -u "$ACCOUNT")
	if [ "$uid" -eq 0 ]; then
		fail "account lindm resolved to UID 0"
	fi
}

check_dir() {
	path=$1
	uid=$2
	gid=$3
	mode=$4
	reject_symlink "$path"
	if [ ! -d "$path" ]; then
		fail "$path is not a directory; refusing to replace protected state"
	fi
	owner=$(stat -c %u -- "$path")
	group=$(stat -c %g -- "$path")
	actual=$(stat -c %a -- "$path")
	if [ "$owner" -ne "$uid" ] || [ "$group" -ne "$gid" ] || [ "$actual" -ne "$mode" ]; then
		fail "$path has incompatible owner or mode; refusing to reset protected state"
	fi
}

ensure_dir() {
	path=$1
	uid=$2
	gid=$3
	mode=$4
	reject_symlink "$path"
	if [ -e "$path" ]; then
		check_dir "$path" "$uid" "$gid" "$mode"
		return 0
	fi
	install -d -o "$uid" -g "$gid" -m "$mode" -- "$path"
	check_dir "$path" "$uid" "$gid" "$mode"
}

configure() {
	if [ ! -x "$BINARY" ]; then
		fail "agent binary is not executable"
	fi
	ensure_account
	account_uid=$(id -u "$ACCOUNT")
	account_gid=$(id -g "$ACCOUNT")
	ensure_dir "$PARENT" 0 0 755
	ensure_dir "$EXECUTOR" 0 0 700
	ensure_dir "$AGENT" "$account_uid" "$account_gid" 700
	ensure_dir "$PARENT/firewall" 0 0 700
	ensure_dir "$PARENT/connectivity-guard" 0 0 700
	if [ -d /run ]; then
		systemd-tmpfiles --create "$TMPFILES" || fail "systemd-tmpfiles failed"
	fi
	# The per-user remote-assistance helper is enabled for every graphical
	# session; it starts only where the executor serves the session socket.
	# --global edits only unit symlinks, so it needs no running manager.
	systemctl --global enable "$SESSION_USER_UNIT" || fail "systemctl --global enable failed"
	if systemd_running; then
		systemctl daemon-reload || fail "systemctl daemon-reload failed"
		# Firewall restoration and its rollback supervisor ship disabled; the
		# firewall resource kind is not qualified and stays server-gated.
		systemctl enable "$EXECUTOR_UNIT" "$AGENT_UNIT" || fail "systemctl enable failed"
		systemctl restart "$EXECUTOR_UNIT" || fail "executor failed to start"
		systemctl restart "$AGENT_UNIT" || fail "network agent failed to start"
	fi
}

stop_units() {
	if systemd_running; then
		systemctl stop "$AGENT_UNIT" "$EXECUTOR_UNIT" "$FIREWALL_RESTORE_UNIT" "$CONNECTIVITY_GUARD_UNIT" || fail "systemctl stop failed"
	fi
}

disable_units() {
	if systemd_running; then
		systemctl disable "$AGENT_UNIT" "$EXECUTOR_UNIT" "$FIREWALL_RESTORE_UNIT" || fail "systemctl disable failed"
	fi
}

upgrade_stop() {
	stop_units
}

remove_services() {
	stop_units
	disable_units
	systemctl --global disable "$SESSION_USER_UNIT" || fail "systemctl --global disable failed"
	if systemd_running; then
		systemctl daemon-reload || fail "systemctl daemon-reload failed"
	fi
}

retain_state() {
	# remove and purge keep /var/lib/lindm/executor, /var/lib/lindm/agent,
	# and the lindm account. No deletion is performed.
	if systemd_running; then
		systemctl daemon-reload || true
	fi
}

base=$(basename "$0")
case "$base" in
*postinst)
	case "${1:-}" in
	configure) configure ;;
	abort-upgrade | abort-remove | abort-deconfigure) exit 0 ;;
	*) fail "unexpected postinst argument" ;;
	esac
	;;
*prerm)
	case "${1:-}" in
	upgrade) upgrade_stop ;;
	remove | deconfigure) remove_services ;;
	failed-upgrade) exit 0 ;;
	*) fail "unexpected prerm argument" ;;
	esac
	;;
*postrm)
	case "${1:-}" in
	remove | purge | upgrade | disappear | failed-upgrade | abort-install | abort-upgrade)
		retain_state
		;;
	*) fail "unexpected postrm argument" ;;
	esac
	;;
*)
	case "${1:-}" in
	configure) configure ;;
	upgrade-stop) upgrade_stop ;;
	remove) remove_services ;;
	*) fail "refusing unexpected lifecycle verb" ;;
	esac
	;;
esac
