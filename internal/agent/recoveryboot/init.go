package recoveryboot

// No original root, interactive shell, alternate init, or credential fallback is
// available. Every failure powers off. All executables are in the signed closure.
const initScript = `#!/bin/busybox sh
set -eu
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
BB=/bin/busybox
fail() { $BB poweroff -f; exit 1; }
trap fail EXIT INT TERM
$BB mount -t devtmpfs devtmpfs /dev
# The archive contains directories, not static device nodes. Rebind PID 1's
# standard streams after devtmpfs creates the kernel-selected console.
exec </dev/console >/dev/console 2>&1
$BB mount -t proc proc /proc
$BB mount -t sysfs sysfs /sys
$BB mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
$BB mkdir -p /sys/firmware/efi/efivars /run/lindm-recovery
# The approved kernel must have storage, EFI, ext4 and network drivers built in;
# optional approved modules can be preloaded through modules.load.
if [ -f /etc/lindm/modules.load ]; then
  while IFS= read -r module; do $BB modprobe "$module"; done < /etc/lindm/modules.load
fi
$BB mount -t efivarfs efivarfs /sys/firmware/efi/efivars
@CUSTODY_SETUP@
@BOOT_IMAGE_SETUP@
# DHCP is bounded. No resolver/script is imported from the destroyed host.
$BB ip link set lo up
online=0
for nic in /sys/class/net/*; do
  iface=${nic##*/}
  [ "$iface" = lo ] && continue
  $BB ip link set "$iface" up
  if $BB udhcpc -n -q -t 5 -T 3 -i "$iface" -s /etc/lindm/udhcpc; then online=1; break; fi
done
[ "$online" = 1 ] || fail
# Native TPM sessions lock current/future process memory; do not inherit the
# kernel's small default memlock ceiling. Failure is fatal before recovery starts.
ulimit -l unlimited
/usr/bin/lindm-agent recovery-run -config /etc/lindm/recovery.json
fail
`

const offTargetSetup = `n=0
state=
while [ "$n" -lt 30 ]; do
  state=$($BB findfs UUID=@STATE_UUID@) && break
  n=$((n + 1))
  $BB sleep 1
done
[ -n "$state" ] || fail
$BB mount -t ext4 -o rw,nosuid,nodev,noexec "$state" /run/lindm-recovery
`

const tpmSetup = `$BB chmod 0700 /run/lindm-recovery
`

// The selected entry is only a safe path selector. Recovery authenticates the
// capsule against TPM NV before parsing, and verifies the copied UKI against the
// signed credential. No action identifier is baked into the reusable image.
const bootImageSetup = `entry=$($BB dd if=/sys/firmware/efi/efivars/LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f bs=1 skip=4 count=512 2>/dev/null | $BB tr -d '\000')
case "$entry" in
  lindm-recovery-????????-????-????-????-????????????.efi) ;;
  *) fail ;;
esac
action=${entry#lindm-recovery-}
action=${action%.efi}
compact=$($BB printf '%s' "$action" | $BB tr -d '-')
[ "${#compact}" = 32 ] || fail
case "$compact" in *[!0-9a-f]*) fail ;; esac
$BB mkdir -p /run/recovery-esp
n=0
esp=
while [ "$n" -lt 30 ]; do
  esp=$($BB findfs UUID=@ESP_UUID@) && break
  n=$((n + 1))
  $BB sleep 1
done
[ -n "$esp" ] || fail
$BB mount -t vfat -o ro,nosuid,nodev,noexec "$esp" /run/recovery-esp
$BB cp "/run/recovery-esp/EFI/Linux/$entry" /run/lindm-recovery/booted.efi
if [ -z '@STATE_UUID@' ]; then
  $BB cp "/run/recovery-esp/EFI/Linux/lindm-recovery-$action.capsule" /run/lindm-recovery/capsule.pb
  $BB chmod 0400 /run/lindm-recovery/capsule.pb
fi
$BB cp /etc/lindm/image-signing.pem /run/lindm-recovery/image-signing.pem
$BB chmod 0400 /run/lindm-recovery/booted.efi /run/lindm-recovery/image-signing.pem
$BB umount /run/recovery-esp
`

const dhcpScript = `#!/bin/busybox sh
set -eu
BB=/bin/busybox
case "$1" in
  deconfig) $BB ip addr flush dev "$interface" ;;
  bound|renew)
    $BB ifconfig "$interface" "$ip" netmask "${subnet:-255.255.255.0}"
    for gateway in ${router:-}; do $BB ip route replace default via "$gateway" dev "$interface"; break; done
    : > /etc/resolv.conf
    for server in ${dns:-}; do printf 'nameserver %s\n' "$server" >> /etc/resolv.conf; done
    ;;
esac
`
