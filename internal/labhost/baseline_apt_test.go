package labhost

import (
	"strings"
	"testing"
)

func TestBaselineOfficialUbuntuSources(t *testing.T) {
	for _, uri := range []string{
		"http://ports.ubuntu.com/ubuntu-ports/",
		"https://archive.ubuntu.com/ubuntu",
		"http://gb.archive.ubuntu.com/ubuntu/",
		"https://security.ubuntu.com/ubuntu/",
	} {
		source := "# distribution source\nTypes: deb\nURIs: " + uri + "\nSuites: noble noble-updates\n noble-security\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
		if err := validateBaselineSources(source, "arm64"); err != nil {
			t.Errorf("rejected signed official source %q: %v", uri, err)
		}
	}
	separate := "Types: deb\nURIs: http://ports.ubuntu.com/ubuntu-ports\nSuites: noble noble-updates noble-backports\nComponents: main universe\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\nTypes: deb\nURIs: http://ports.ubuntu.com/ubuntu-ports\nSuites: noble-security\nComponents: main universe\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
	if err := validateBaselineSources(separate, "arm64"); err != nil {
		t.Fatalf("rejected separate security stanza: %v", err)
	}
}

func TestBaselineRejectsExpandedOrWeakenedAPTTrust(t *testing.T) {
	valid := "Types: deb\nURIs: https://ports.ubuntu.com/ubuntu-ports\nSuites: noble noble-updates noble-security\nComponents: main universe\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
	cases := map[string]string{
		"third party":             strings.Replace(valid, "https://ports.ubuntu.com/ubuntu-ports", "https://cli.github.com/packages", 1),
		"mixed URI":               strings.Replace(valid, "https://ports.ubuntu.com/ubuntu-ports", "https://ports.ubuntu.com/ubuntu-ports https://cli.github.com/packages", 1),
		"lookalike domain":        strings.Replace(valid, "ports.ubuntu.com", "ports.ubuntu.com.example.org", 1),
		"userinfo":                strings.Replace(valid, "ports.ubuntu.com", "user@ports.ubuntu.com", 1),
		"nonstandard port":        strings.Replace(valid, "ports.ubuntu.com", "ports.ubuntu.com:8443", 1),
		"wrong archive path":      strings.Replace(valid, "ubuntu-ports", "unreviewed", 1),
		"other keyring":           strings.Replace(valid, "/usr/share/keyrings/ubuntu-archive-keyring.gpg", "/etc/apt/trusted.gpg", 1),
		"trusted override":        valid + "Trusted: yes\n",
		"validity bypass":         valid + "Check-Valid-Until: no\n",
		"insecure override":       valid + "Allow-Insecure: yes\n",
		"wrong suite":             strings.Replace(valid, "noble-updates", "jammy-updates", 1),
		"missing security":        strings.Replace(valid, " noble-security", "", 1),
		"disabled":                valid + "Enabled: no\n",
		"wrong architecture":      valid + "Architectures: amd64\n",
		"duplicate key":           valid + "Signed-By: /tmp/other.gpg\n",
		"mixed stanza":            valid + "\nTypes: deb\nURIs: https://cli.github.com/packages\nSuites: noble\nComponents: main universe\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n",
		"missing binary packages": strings.Replace(valid, "Types: deb", "Types: deb-src", 1),
		"missing universe":        strings.Replace(valid, "main universe", "main", 1),
		"orphan continuation":     " continuation\n" + valid,
		"malformed field":         valid + "not a field\n",
		"empty":                   "",
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateBaselineSources(source, "arm64"); err == nil {
				t.Fatal("accepted a source configuration outside the signed official Ubuntu baseline")
			}
		})
	}
}
