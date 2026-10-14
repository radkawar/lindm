// SPDX-License-Identifier: Apache-2.0

// window.location.hostname is URL-normalized: IPv6 literals are bracketed and
// IPv4 literals have four decimal octets. DNS names must not be guessed from dots.
export function consoleSetupDNSWarning(hostname: string): string | null {
  const ipv6 = hostname.startsWith("[") && hostname.endsWith("]");
  const ipv4 =
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) &&
    hostname.split(".").every((octet) => Number(octet) <= 255);
  return ipv4 || ipv6
    ? "Passkey setup requires a DNS name, not an IP address. Configure the console DNS name and its HTTPS certificate, then open that address before creating the owner account."
    : null;
}
