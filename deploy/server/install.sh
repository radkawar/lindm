#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Execute only from a bundle whose installer signature was authenticated through
# the release owner's independent distribution channel. The bundle's own key is
# not authority. This small wrapper uses host-maintained OpenSSL before executing
# any bundled program, and snapshots bytes into root-only custody.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'Run with sudo from the independently authenticated bundle.' >&2; exit 1; }
bundle=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
key=''
pin=''
origin=''
recipient=''
previous=''
for value in "$@"; do
  case "$previous" in
    --release-key-file) key=$value ;;
    --release-key-id) pin=$value ;;
    --origin) origin=$value ;;
    --backup-recipient-file) recipient=$value ;;
  esac
  previous=$value
done
prompt() {
  [ -r /dev/tty ] && [ -w /dev/tty ] || { printf '%s\n' 'Explicit flags required without a private terminal.' >&2; exit 1; }
  printf '%s: ' "$1" > /dev/tty
  IFS= read -r answer < /dev/tty
}
if [ -z "$key" ]; then prompt 'Independent release public-key file'; key=$answer; set -- "$@" --release-key-file "$key"; fi
if [ -z "$pin" ]; then prompt 'Independent release key SPKI SHA256'; pin=$answer; set -- "$@" --release-key-id "$pin"; fi
if [ -z "$origin" ]; then prompt 'Console HTTPS origin (for example https://mdm.example:18444)'; origin=$answer; set -- "$@" --origin "$origin"; fi
if [ -z "$recipient" ]; then prompt 'Offline custodian age public-recipient file'; recipient=$answer; set -- "$@" --backup-recipient-file "$recipient"; fi
case "$pin" in *[!0-9a-f]*|'') printf '%s\n' 'Invalid independent key pin.' >&2; exit 1;; esac
[ "${#pin}" -eq 64 ] || exit 1
work=$(mktemp -d /var/lib/lindm-install.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
cp -- "$key" "$work/release.pub"
cp -- "$recipient" "$work/backup-recipient"
# Rebuild the original argument vector, replacing only public root-recipient
# inputs with immutable root copies. Repeated flags remain repeated exactly once.
remaining=$#
root_recipient_count=0
while [ "$remaining" -gt 0 ]; do
  value=$1
  shift
  remaining=$((remaining - 1))
  case "$value" in
    --execution-root-recipient-file|-execution-root-recipient-file)
      [ "$remaining" -gt 0 ] || exit 1
      input=$1
      shift
      remaining=$((remaining - 1))
      ;;
    --execution-root-recipient-file=*|-execution-root-recipient-file=*) input=${value#*=} ;;
    *) set -- "$@" "$value"; continue ;;
  esac
  root_recipient_count=$((root_recipient_count + 1))
  [ "$root_recipient_count" -le 3 ] || exit 1
  cp -- "$input" "$work/root-recipient-$root_recipient_count"
  set -- "$@" --execution-root-recipient-file "$work/root-recipient-$root_recipient_count"
done
openssl pkey -pubin -in "$work/release.pub" -outform DER -out "$work/release.der"
actual=$(sha256sum "$work/release.der")
actual=${actual%% *}
[ "$actual" = "$pin" ] || { printf '%s\n' 'Independent release key pin mismatch.' >&2; exit 1; }
# Copy first; all later checks and transactions use only this immutable snapshot.
mkdir "$work/bundle"
cp -R --no-dereference --no-preserve=ownership -- "$bundle/." "$work/bundle/"
chmod -R go-w -- "$work/bundle"
bad_entry=$(find "$work/bundle" ! -type d ! -type f -print -quit)
[ -z "$bad_entry" ] || { printf '%s\n' 'Bundle links and special files are forbidden.' >&2; exit 1; }
openssl pkeyutl -verify -pubin -inkey "$work/release.pub" -rawin -in "$work/bundle/installer.sha256" -sigfile "$work/bundle/installer.sha256.sig"
# Six bootstrap assets are mandatory; each offline add-on adds an exact pair.
lines=$(wc -l < "$work/bundle/installer.sha256")
[ "$lines" -eq 6 ] || [ "$lines" -eq 8 ] || [ "$lines" -eq 10 ] || exit 1
seen=' '
while IFS= read -r line; do
  sum=${line%%  *}
  name=${line#*  }
  [ "${#sum}" -eq 64 ] || exit 1
  case "$sum" in *[!0-9a-f]*) exit 1;; esac
  case "$name" in install.sh|lindm-install|release-root.json|release.json|ubuntu24.04.snapshot|rhel9.snapshot|ubuntu24.04.snapshot.digest|rhel9.snapshot.digest|agent-repository/package-signing.asc|native-package.fingerprint) ;; *) exit 1;; esac
  case "$seen" in *" $name "*) printf '%s\n' 'Duplicate signed installer asset.' >&2; exit 1;; esac
  seen="${seen}${name} "
done < "$work/bundle/installer.sha256"
has_asset() { case "$seen" in *" $1 "*) return 0;; *) return 1;; esac; }
for required in install.sh lindm-install release-root.json release.json agent-repository/package-signing.asc native-package.fingerprint; do
  has_asset "$required" || { printf '%s\n' 'Mandatory signed installer asset missing.' >&2; exit 1; }
done
for snapshot in ubuntu24.04.snapshot rhel9.snapshot; do
  if has_asset "$snapshot"; then
    has_asset "$snapshot.digest" || { printf '%s\n' 'Incomplete signed offline add-on.' >&2; exit 1; }
  elif has_asset "$snapshot.digest"; then
    printf '%s\n' 'Incomplete signed offline add-on.' >&2; exit 1
  fi
done
(cd "$work/bundle" && sha256sum --strict --check installer.sha256)
# Independent public key is copied to a root-owned immutable path before the Go
# verifier checks the full release and all signed supplemental assets again.
"$work/bundle/lindm-install" "$@" --bundle "$work/bundle" --release-key-file "$work/release.pub" --backup-recipient-file "$work/backup-recipient"
