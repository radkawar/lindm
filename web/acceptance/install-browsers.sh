#!/bin/bash
# Explicitly authorized host setup, not a browser acceptance result. Invoke via
# lab hosts baseline-browser so before/after output survives partial failure.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
. /etc/os-release
if [[ "$ID" != ubuntu || "$VERSION_ID" != 24.04 ]]; then
  echo 'browser baseline currently requires Ubuntu 24.04' >&2
  exit 1
fi
if [[ "$(id -u)" == 0 ]]; then
  echo 'run as the intended unprivileged browser user; setup uses sudo -n' >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64)
    firefox_arch=linux-x86_64
    firefox_sha=ebec5e5c91a7c954a0f276928748bb4249e2b44bccdcfe6c7d7b4ed9c64ca6891a56cc8a016546bfbf1ca537dfe6084dba8f2746037c62fae0acc13a542421f3
    gecko_arch=linux64
    gecko_sha=e815130ea95983e162ae91843b48d3a3ce991735635fce83a647afde21e09f7e
    ;;
  aarch64)
    firefox_arch=linux-aarch64
    firefox_sha=8d8cea53ceea62b1f11d4d4345190a31611e90a7a3b921f096da6515bdb0ad60e5a311a06a193b67fc993c18debf78aa67aa314de685da9c66bb9b4d0640d422
    gecko_arch=linux-aarch64
    gecko_sha=8fd90b951422fbad5b56539fb344dff66eb3f986d615d8d6fde9f1f62dad610c
    ;;
  *) echo 'browser baseline supports x86_64/aarch64 only' >&2; exit 1 ;;
esac
packages=(ca-certificates curl xz-utils bzip2 libgtk-3-0t64 libdbus-glib-1-2 libasound2t64 webkit2gtk-driver libwebkit2gtk-4.1-0 xvfb xauth)
observe_packages() {
  for package in "${packages[@]}"; do
    dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$package" 2>/dev/null || printf '%s\tnot-installed\n' "$package"
  done
}
echo '=== packages before ==='
observe_packages
# No trust override, repository edit, package removal or distribution upgrade.
apt_options=(-o DPkg::Lock::Timeout=300 -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false)
sudo -n apt-get "${apt_options[@]}" update
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get "${apt_options[@]}" --no-remove -y install "${packages[@]}"
echo '=== packages after ==='
observe_packages
root="$HOME/.local/share/lindm/acceptance-browsers"
install -d -m 0700 "$root"
work="$(mktemp -d "$root/.download.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-time 600 \
  "https://archive.mozilla.org/pub/firefox/releases/157.0.1/$firefox_arch/en-US/firefox-157.0.1.tar.xz" -o "$work/firefox.tar.xz"
printf '%s  %s\n' "$firefox_sha" "$work/firefox.tar.xz" | sha512sum --check --strict
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-time 120 \
  "https://github.com/mozilla/geckodriver/releases/download/v0.37.1/geckodriver-v0.37.1-$gecko_arch.tar.gz" -o "$work/geckodriver.tar.gz"
printf '%s  %s\n' "$gecko_sha" "$work/geckodriver.tar.gz" | sha256sum --check --strict
tar --no-same-owner -xJf "$work/firefox.tar.xz" -C "$work"
tar --no-same-owner -xzf "$work/geckodriver.tar.gz" -C "$work" geckodriver
# Versioned private paths avoid changing the operator's browser or running VM.
# An existing installation is retained, never recursively overwritten.
if [[ ! -e "$root/firefox-157.0.1" ]]; then
  mkdir -m 0700 "$root/firefox-157.0.1"
  mv "$work/firefox" "$root/firefox-157.0.1/firefox"
fi
if [[ ! -e "$root/geckodriver-0.37.1" ]]; then
  install -m 0700 "$work/geckodriver" "$root/geckodriver-0.37.1"
fi
echo '=== native browser binaries ==='
printf 'firefoxBinary=%s\ngeckodriverBinary=%s\n' "$root/firefox-157.0.1/firefox/firefox" "$root/geckodriver-0.37.1"
"$root/firefox-157.0.1/firefox/firefox" --version
"$root/geckodriver-0.37.1" --version
dpkg-query -W -f='WebKitWebDriver ${Version}\n' webkit2gtk-driver
printf 'webkitDriverBinary=%s\n' "$(command -v WebKitWebDriver)"
for minibrowser in /usr/lib/*/webkit2gtk-4.1/MiniBrowser; do
  if [[ -x "$minibrowser" ]]; then printf 'webkitBrowserBinary=%s\n' "$minibrowser"; fi
done
echo 'Native WebAuthn support is qualified only by the actual acceptance journey, not installation.'
