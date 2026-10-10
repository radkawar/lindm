#!/bin/sh
# No installation or upgrade starts/enables services, performs DDL or bootstraps
# an owner. Operator config, credentials, Unix accounts and database survive purge.
set -eu
cd / || exit 1
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

fail() {
	printf 'lindmd: %s\n' "$1" >&2
	exit 1
}

check_dir() {
	if [ -L "$1" ] || [ ! -d "$1" ]; then
		fail "$1 is not a protected directory"
	fi
	[ "$(stat -c %u -- "$1")" -eq 0 ] || fail "$1 must belong to root"
	[ "$(stat -c %g -- "$1")" -eq "$2" ] || fail "$1 has an incompatible group"
	[ "$(stat -c %a -- "$1")" = "$3" ] || fail "$1 has an incompatible mode"
}

ensure_dir() {
	[ ! -L "$1" ] || fail "$1 is a symlink"
	if [ ! -e "$1" ]; then
		install -d -o 0 -g "$2" -m "$3" -- "$1"
	fi
	check_dir "$1" "$2" "$3"
}

reload() {
	if [ -d /run/systemd/system ]; then
		systemctl daemon-reload || fail "systemctl daemon-reload failed"
	fi
}

configure() {
	check_dir /etc 0 755
	systemd-sysusers /usr/lib/sysusers.d/lindmd.conf || fail "systemd-sysusers failed"
	runtime_uid=$(id -u lindmd)
	migrator_uid=$(id -u lindmd-migrate)
	runtime_gid=$(id -g lindmd)
	migrator_gid=$(id -g lindmd-migrate)
	if [ "$runtime_uid" -eq 0 ] || [ "$migrator_uid" -eq 0 ] || [ "$runtime_uid" -eq "$migrator_uid" ]; then
		fail "server accounts must be distinct non-root identities"
	fi
	if [ "$runtime_gid" -eq 0 ] || [ "$migrator_gid" -eq 0 ] || [ "$runtime_gid" -eq "$migrator_gid" ]; then
		fail "server groups must be distinct non-root groups"
	fi
	# Preserve every existing operator file and refuse incompatible custody.
	ensure_dir /etc/lindm 0 755
	ensure_dir /etc/lindm/migrate "$migrator_gid" 750
	reload
}

remove_services() {
	if [ -d /run/systemd/system ]; then
		systemctl stop lindmd.service lindmd-migrate.service || fail "systemctl stop failed"
		systemctl disable lindmd.service || fail "systemctl disable failed"
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
	remove | deconfigure) remove_services ;;
	upgrade | failed-upgrade) exit 0 ;;
	*) fail "unexpected prerm argument" ;;
	esac
	;;
*postrm)
	case "${1:-}" in
	remove | purge | upgrade | disappear | failed-upgrade | abort-install | abort-upgrade) reload ;;
	*) fail "unexpected postrm argument" ;;
	esac
	;;
*)
	case "${1:-}" in
	configure) configure ;;
	remove) remove_services ;;
	*) fail "unexpected lifecycle verb" ;;
	esac
	;;
esac
