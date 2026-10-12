import type { FieldHints } from "@/lib/validation";

// Material rules are regular expressions; show what to enter instead of the
// pattern. Violation text names fields and rules only; it never echoes material.
export const secretMaterialHints: FieldHints = {
  "material.password_hash":
    "Enter a crypt(3) hash, not the password: yescrypt ($y$…), SHA-512 ($6$…) or bcrypt ($2b$…).",
  "material.wifi_psk":
    "Enter an 8 to 63 character printable WPA passphrase or a 64-digit hexadecimal PSK.",
};
