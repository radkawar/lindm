#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# This gate is embedded in DEB preinst and RPM pretrans, before replacing bytes.
# Root compromise is out of scope; unattended native transactions cannot bypass
# the installer's authenticated preflight and successful encrypted backup.
set -eu
set -f
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
deny() {
  printf '%s\n' 'lindmd upgrade requires the signed bundle installer and encrypted backup.' >&2
  exit 1
}
if [ -e /usr/bin/lindmd ] || [ -e /etc/lindm/server.json ]; then
  authorization=/run/lindm-install/authorized-version
  [ ! -L /run/lindm-install ] && [ -d /run/lindm-install ] || deny
  [ "$(stat -c '%u:%a' /run/lindm-install)" = '0:700' ] || deny
  [ ! -L "$authorization" ] && [ -f "$authorization" ] || deny
  [ "$(stat -c '%u:%a' "$authorization")" = '0:600' ] || deny
  {
    IFS= read -r version
    IFS= read -r installer_pid
    IFS= read -r installer_start
  } < "$authorization"
  [ "$version" = '@LINDM_VERSION@' ] || deny
  case "$installer_pid:$installer_start" in *[!0-9:]*|:*|*:) deny;; esac
  current=$$
  depth=0
  admitted=false
  while [ "$current" -gt 0 ] && [ "$depth" -lt 64 ]; do
    if [ "$current" = "$installer_pid" ]; then
      IFS= read -r process_stat < "/proc/$current/stat"
      process_fields=${process_stat##*) }
      # /proc stat field 22 is word 20 after pid and parenthesized comm.
      # Intentional splitting of kernel fields; pathname expansion is disabled.
      # shellcheck disable=SC2086
      set -- $process_fields
      [ "$#" -ge 20 ] || deny
      shift 19
      [ "$1" = "$installer_start" ] || deny
      admitted=true
      break
    fi
    parent=''
    while IFS= read -r line; do
      # shellcheck disable=SC2086
      case "$line" in PPid:*) set -- $line; parent=$2; break;; esac
    done < "/proc/$current/status"
    [ -n "$parent" ] || deny
    current=$parent
    depth=$((depth + 1))
  done
  [ "$admitted" = true ] || deny
  rm -- "$authorization"
fi
