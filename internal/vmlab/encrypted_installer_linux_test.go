package vmlab

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func encryptedInstallerTestKeys(t *testing.T) (string, string, string) {
	t.Helper()
	loginPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	hostPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	login, err := ssh.NewSignerFromKey(loginPrivate)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(hostPrivate, "")
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(login.PublicKey())), string(pem.EncodeToMemory(block)), string(ssh.MarshalAuthorizedKey(host.PublicKey()))
}

func TestEncryptedUbuntuRecipe(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	passphrase := `quotes'"; $(touch /must-not-exist) # : [] {}`
	recipe, err := encryptedInstallerRecipe("ubuntu", passphrase, login, private, public)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Autoinstall struct {
			Version int `json:"version"`
			Storage struct {
				Layout struct {
					Name     string            `json:"name"`
					Password string            `json:"password"`
					Sizing   string            `json:"sizing-policy"`
					Match    map[string]string `json:"match"`
				} `json:"layout"`
			} `json:"storage"`
			Identity map[string]string `json:"identity"`
			SSH      struct {
				Install  bool     `json:"install-server"`
				Password bool     `json:"allow-pw"`
				Keys     []string `json:"authorized-keys"`
			} `json:"ssh"`
			UserData struct {
				DeleteKeys bool     `json:"ssh_deletekeys"`
				KeyTypes   []string `json:"ssh_genkeytypes"`
			} `json:"user-data"`
			Commands [][]string `json:"late-commands"`
			Shutdown string     `json:"shutdown"`
		} `json:"autoinstall"`
	}
	if !bytes.HasPrefix(recipe, []byte("#cloud-config\n")) {
		t.Fatal("NoCloud input lacks cloud-config header")
	}
	if err := json.Unmarshal(bytes.TrimPrefix(recipe, []byte("#cloud-config\n")), &config); err != nil {
		t.Fatal(err)
	}
	a := config.Autoinstall
	if a.Version != 1 || a.Storage.Layout.Name != "lvm" || a.Storage.Layout.Password != passphrase || a.Storage.Layout.Sizing != "all" || a.Storage.Layout.Match["path"] != "/dev/vda" {
		t.Fatal("autoinstall does not bind encrypted LVM to the guest disk")
	}
	if a.Identity["username"] != "lindm-lab" || a.Identity["password"] != "!" || !a.SSH.Install || a.SSH.Password || len(a.SSH.Keys) != 1 || a.SSH.Keys[0] != strings.TrimSpace(login) || a.Shutdown != "poweroff" {
		t.Fatal("autoinstall lost pinned key-only user or shutdown")
	}
	if a.UserData.DeleteKeys || len(a.UserData.KeyTypes) != 1 || a.UserData.KeyTypes[0] != "ed25519" {
		t.Fatal("cloud-init must preserve the pinned key using its nonempty key-type schema")
	}
	if len(a.Commands) != 1 || len(a.Commands[0]) != 8 || strings.Join(a.Commands[0][:7], " ") != "curtin in-target --target=/target -- /bin/sh -eu -c" {
		t.Fatal("provisioning must execute in the installed guest root")
	}
	script := a.Commands[0][7]
	if strings.Contains(script, passphrase) {
		t.Fatal("disk passphrase leaked into provisioning command syntax")
	}
	for _, required := range []string{"console=ttyS0,115200n8", "update-initramfs -u -k all", "update-grub", "ssh_deletekeys: false", "emit_keys_to_console: false"} {
		if !strings.Contains(script, required) {
			t.Errorf("guest provisioning lacks %q", required)
		}
	}
	// Parse the actual generated shell program, never run its guest mutations.
	cmd := exec.Command("/bin/sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("invalid guest shell syntax: %v: %s", err, out)
	}
}

func TestEncryptedFedoraRecipe(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, passphrase := range []string{"lab-passphrase", `quote'"; $(exit 99) # --nohome`, `spaces and \\ backslashes`} {
		recipe, err := encryptedInstallerRecipe("fedora", passphrase, login, private, public)
		if err != nil {
			t.Fatal(err)
		}
		text := string(recipe)
		var autopart string
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "autopart ") {
				autopart = line
			}
		}
		// Kickstart uses POSIX shlex tokenization. Exercise metacharacters with
		// the corresponding shell tokenizer; expansion would make this fail.
		cmd := exec.Command("/bin/sh", "-eu", "-c", "set -- "+autopart+"\nprintf '%s\\000' \"$@\"")
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
		want := []string{"autopart", "--type=lvm", "--encrypted", "--luks-version=luks2", "--passphrase=" + passphrase}
		if len(got) != len(want) {
			t.Fatal("passphrase changed kickstart token count")
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("kickstart token %d was altered", i)
			}
		}
		for _, required := range []string{"\ncdrom\n", "\nignoredisk --only-use=vda\n", "\nclearpart --all --initlabel --drives=vda\n", "console=ttyS0,115200n8", "\npoweroff\n", "\n%post --erroronfail --interpreter=/bin/sh\n", "dracut --regenerate-all --force", "restorecon -RF"} {
			if !strings.Contains(text, required) {
				t.Errorf("kickstart lacks %q", required)
			}
		}
		_, post, ok := strings.Cut(text, "%post --erroronfail --interpreter=/bin/sh\n")
		if !ok {
			t.Fatal("missing guest provisioning")
		}
		cmd = exec.Command("/bin/sh", "-n")
		cmd.Stdin = strings.NewReader(strings.TrimSuffix(post, "%end\n"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("invalid guest shell syntax: %v: %s", err, out)
		}
	}
}

func TestEncryptedRecipeRejectsInjectionAndMismatchedKeys(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, distribution := range []string{"ubuntu", "fedora"} {
		for _, tc := range []struct{ pass, login, private, public string }{
			{"", login, private, public},
			{"secret\npoweroff", login, private, public},
			{"secret\rpoweroff", login, private, public},
			{"secret\x00suffix", login, private, public},
			{"secret", login + "%post\n", private, public},
			{"secret", "command=\"bad\" " + login, private, public},
			{"secret", login, private, login},
			{"secret", login, "sensitive-invalid-private-key", public},
		} {
			_, err := encryptedInstallerRecipe(distribution, tc.pass, tc.login, tc.private, tc.public)
			if err == nil {
				t.Fatal("unsafe installer input was accepted")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "sensitive-invalid-private-key") {
				t.Fatal("input secret leaked into error")
			}
		}
	}
}

func TestEncryptedInstallerGRUBPreservesVendorBootPayload(t *testing.T) {
	for _, distribution := range []string{"ubuntu", "fedora"} {
		input := []byte("set default=1\nset timeout=60\nmenuentry 'vendor installer' {\n linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=Fedora-Server quiet rhgb rd.live.check ---\n initrdefi /images/pxeboot/initrd.img\n}\n")
		got, err := encryptedInstallerGRUB(input, distribution)
		if err != nil {
			t.Fatal(err)
		}
		text := string(got)
		for _, want := range []string{"linuxefi /images/pxeboot/vmlinuz", "inst.stage2=hd:LABEL=Fedora-Server", "initrdefi /images/pxeboot/initrd.img", "console=ttyS0,115200n8", "set timeout=1", "set default=0"} {
			if !strings.Contains(text, want) {
				t.Errorf("patched boot configuration lost %q", want)
			}
		}
		for _, unwanted := range []string{" quiet", " rhgb", "rd.live.check", "set timeout=60", "set default=1"} {
			if strings.Contains(text, unwanted) {
				t.Errorf("patched boot configuration retained %q", unwanted)
			}
		}
		if distribution == "ubuntu" && !strings.Contains(text, "autoinstall noprompt ds=nocloud\\;s=/cdrom/lindm-seed/") {
			t.Fatal("unattended shutdown or NoCloud kernel input is missing, or GRUB semicolon unescaped")
		}
		if distribution == "fedora" && !strings.Contains(text, "inst.ks=cdrom:/lindm-seed/ks.cfg inst.text") {
			t.Fatal("kickstart kernel input is missing")
		}
	}
	if _, err := encryptedInstallerGRUB([]byte("menuentry 'no kernel' {}"), "ubuntu"); err == nil {
		t.Fatal("accepted an unpatchable vendor boot configuration")
	}
}

func TestEncryptedInstallerEFIOffset(t *testing.T) {
	report := "El Torito boot img : 1 BIOS y none 0x0000 0x00 4 20\nEl Torito boot img : 2 UEFI y none 0x0000 0x00 10136 43\n"
	offset, err := encryptedInstallerEFIOffset([]byte(report))
	if err != nil || offset != 43*2048 {
		t.Fatalf("EFI byte offset = %d, error %v", offset, err)
	}
	for _, invalid := range []string{"", "El Torito boot img : 2 UEFI y none 0x0000 0x00 10136 -1\n", report + report} {
		if _, err := encryptedInstallerEFIOffset([]byte(invalid)); err == nil {
			t.Fatal("accepted missing, invalid or ambiguous EFI boot image")
		}
	}
}

func TestEncryptedInstallerManifests(t *testing.T) {
	for _, filename := range []string{"ubuntu-noble-encrypted-amd64.json", "fedora-44-encrypted-x86_64.json", "ubuntu-noble-encrypted-arm64.json", "fedora-44-encrypted-aarch64.json"} {
		manifest, err := LoadManifest("../../lab/images/" + filename)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(manifest.GetImageFilename(), ".iso") || manifest.GetImageSizeBytes() < 1<<30 || manifest.GetSignerProvenanceUrl() == "" || manifest.GetReleaseProvenanceUrl() == "" {
			t.Fatal("installer acquisition lacks a pinned vendor ISO and provenance")
		}
	}
}

func TestEncryptedInstallerDesktopRecipes(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, distribution := range []string{"ubuntu", "fedora"} {
		for _, desktop := range []string{"gnome", "kde"} {
			t.Run(distribution+"/"+desktop, func(t *testing.T) {
				recipe, err := encryptedInstallerRecipeWithDesktop(distribution, "lab-passphrase", login, private, public, desktop)
				if err != nil {
					t.Fatal(err)
				}
				var script string
				if distribution == "ubuntu" {
					var config struct {
						Autoinstall struct {
							Packages []string   `json:"packages"`
							Commands [][]string `json:"late-commands"`
						} `json:"autoinstall"`
					}
					if err := json.Unmarshal(bytes.TrimPrefix(recipe, []byte("#cloud-config\n")), &config); err != nil {
						t.Fatal(err)
					}
					want := "ubuntu-desktop-minimal"
					if desktop == "kde" {
						want = "kubuntu-desktop"
					}
					found := false
					for _, pkg := range config.Autoinstall.Packages {
						found = found || pkg == want
					}
					if !found {
						t.Fatalf("installer does not install %s", want)
					}
					if len(config.Autoinstall.Commands) != 1 || len(config.Autoinstall.Commands[0]) != 8 {
						t.Fatal("missing installed-root provisioning")
					}
					script = config.Autoinstall.Commands[0][7]
				} else {
					_, post, ok := strings.Cut(string(recipe), "%post --erroronfail --interpreter=/bin/sh\n")
					if !ok {
						t.Fatal("missing installer post transaction")
					}
					script = strings.TrimSuffix(post, "%end\n")
					for _, required := range []string{
						"https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/x86_64/os/",
						"--setopt=lindm-desktop.gpgcheck=1",
						"RPM-GPG-KEY-fedora-44-x86_64",
						"--enable-repo=lindm-desktop",
						desktop + "-desktop",
						"hostonly=\"no\"",
					} {
						if !strings.Contains(script, required) {
							t.Errorf("Fedora installer lacks %q", required)
						}
					}
					if strings.Contains(script, "--nogpgcheck") || strings.Contains(script, "gpgcheck=0") {
						t.Fatal("desktop package signatures were disabled")
					}
				}
				if !strings.Contains(script, "systemctl set-default graphical.target") {
					t.Fatal("desktop will not start at boot")
				}
				if desktop == "gnome" {
					if !strings.Contains(script, "AutomaticLoginEnable=True\nAutomaticLogin=lindm-lab\n") {
						t.Fatal("GDM lacks lab automatic login")
					}
				} else if !strings.Contains(script, "[Autologin]\nUser=lindm-lab\nSession=plasma.desktop\nRelogin=false\n") {
					t.Fatal("SDDM lacks lab Plasma automatic login")
				}
				cmd := exec.Command("/bin/sh", "-n")
				cmd.Stdin = strings.NewReader(script)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("invalid desktop provisioning syntax: %v: %s", err, out)
				}
			})
		}
		plain, err := encryptedInstallerRecipe(distribution, "lab-passphrase", login, private, public)
		if err != nil {
			t.Fatal(err)
		}
		desktop, err := encryptedInstallerRecipeWithDesktop(distribution, "lab-passphrase", login, private, public, "")
		if err != nil || !bytes.Equal(plain, desktop) {
			t.Fatal("empty desktop changes the headless installer contract")
		}
		if _, err := encryptedInstallerRecipeWithDesktop(distribution, "lab-passphrase", login, private, public, "gnome\n%post"); err == nil {
			t.Fatal("accepted desktop command injection")
		}
	}
}

func TestEncryptedInstallerTPMBootRecipes(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, distribution := range []string{"ubuntu", "fedora"} {
		for _, desktop := range []string{"", "gnome", "kde"} {
			t.Run(distribution+"/"+desktop, func(t *testing.T) {
				recipe, err := encryptedInstallerRecipeWithOptions(distribution, "lab-passphrase", login, private, public, desktop, true)
				if err != nil {
					t.Fatal(err)
				}
				var script string
				if distribution == "ubuntu" {
					var config struct {
						Autoinstall struct {
							Commands [][]string `json:"late-commands"`
						} `json:"autoinstall"`
					}
					if err := json.Unmarshal(bytes.TrimPrefix(recipe, []byte("#cloud-config\n")), &config); err != nil {
						t.Fatal(err)
					}
					if len(config.Autoinstall.Commands) != 1 || len(config.Autoinstall.Commands[0]) != 8 {
						t.Fatal("missing installed-root provisioning")
					}
					script = config.Autoinstall.Commands[0][7]
					for _, required := range []string{
						"apt-get -y install dracut systemd tpm2-tools libtss2-tcti-device0t64 cryptsetup-initramfs-",
						"dracut --force \"/boot/initrd.img-$kernel\" \"$kernel\"",
						"update-grub",
					} {
						if !strings.Contains(script, required) {
							t.Errorf("Ubuntu TPM initramfs lacks %q", required)
						}
					}
					if strings.Contains(script, "update-initramfs -u") {
						t.Fatal("TPM-capable Ubuntu still regenerates the stock initramfs")
					}
				} else {
					_, post, ok := strings.Cut(string(recipe), "%post --erroronfail --interpreter=/bin/sh\n")
					if !ok {
						t.Fatal("missing installed-root provisioning")
					}
					script = strings.TrimSuffix(post, "%end\n")
					for _, required := range []string{
						"install systemd-udev tpm2-tools tpm2-tss",
						"--setopt=lindm-tpm.gpgcheck=1",
						"systemd-cryptsetup",
						"dracut --regenerate-all --force",
					} {
						if !strings.Contains(script, required) {
							t.Errorf("Fedora TPM initramfs lacks %q", required)
						}
					}
				}
				for _, required := range []string{
					"systemd crypt tpm2-tss lvm",
					"install_items+=\" /etc/crypttab \"",
					"hostonly=\"no\"",
					"tpm2-device=auto",
				} {
					if !strings.Contains(script, required) {
						t.Errorf("TPM early userspace lacks %q", required)
					}
				}
				if strings.Contains(script, "cryptenroll") || strings.Contains(script, "luksAddKey") || strings.Contains(script, "lab-passphrase") {
					t.Fatal("installer attempted enrollment or copied the passphrase into a command")
				}
				cmd := exec.Command("/bin/sh", "-n")
				cmd.Stdin = strings.NewReader(script)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("invalid TPM provisioning syntax: %v: %s", err, out)
				}
				stock, err := encryptedInstallerRecipeWithDesktop(distribution, "lab-passphrase", login, private, public, desktop)
				if err != nil {
					t.Fatal(err)
				}
				disabled, err := encryptedInstallerRecipeWithOptions(distribution, "lab-passphrase", login, private, public, desktop, false)
				if err != nil || !bytes.Equal(stock, disabled) {
					t.Fatal("disabled TPM bootstrap changes the existing installer")
				}
				if bytes.Contains(disabled, []byte("tpm2-device=auto")) {
					t.Fatal("stock negative lane silently enabled TPM unlock")
				}
			})
		}
	}
}

func TestEncryptedInstallerTPMCrypttabPreservesIdentity(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{
			"# installed by curtin\ncryptroot UUID=1111-2222 none luks,discard,initramfs\n",
			"# installed by curtin\ncryptroot UUID=1111-2222 none luks,discard,tpm2-device=auto\n",
		},
		{
			"luks-123 UUID=123 none discard\nluks-456 UUID=456 - luks,tpm2-device=/dev/tpmrm0\n",
			"luks-123 UUID=123 none discard,tpm2-device=auto\nluks-456 UUID=456 - luks,tpm2-device=auto\n",
		},
		{"root UUID=abc\n", "root UUID=abc none tpm2-device=auto\n"},
	} {
		cmd := exec.Command("awk", encryptedInstallerTPMCrypttabProgram)
		cmd.Stdin = strings.NewReader(tc.input)
		out, err := cmd.Output()
		if err != nil || string(out) != tc.want {
			t.Fatalf("crypttab transform returned %q, %v; want %q", out, err, tc.want)
		}
	}
	for _, invalid := range []string{"", "# no mapping\n", "root\n", "root /dev/vda3 none luks\n", "root UUID=a none luks extra\n"} {
		cmd := exec.Command("awk", encryptedInstallerTPMCrypttabProgram)
		cmd.Stdin = strings.NewReader(invalid)
		if err := cmd.Run(); err == nil {
			t.Fatal("accepted crypttab without unambiguous persistent mapping")
		}
	}
}

func TestEncryptedInstallerARMRecipes(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	// An architecture adaptation must not do textual replacement across secrets.
	passphrase := "ttyS0,115200n8 x86_64 secret"
	for _, distribution := range []string{"ubuntu", "fedora"} {
		for _, desktop := range []string{"", "gnome", "kde"} {
			for _, tpmBoot := range []bool{false, true} {
				recipe, err := encryptedInstallerRecipeForMachine(distribution, passphrase, login, private, public, desktop, tpmBoot, "aarch64")
				if err != nil {
					t.Fatal(err)
				}
				var script string
				if distribution == "ubuntu" {
					var config struct {
						Autoinstall struct {
							Commands [][]string `json:"late-commands"`
							Storage  struct {
								Layout struct {
									Password string            `json:"password"`
									Match    map[string]string `json:"match"`
								} `json:"layout"`
							} `json:"storage"`
						} `json:"autoinstall"`
					}
					if err := json.Unmarshal(bytes.TrimPrefix(recipe, []byte("#cloud-config\n")), &config); err != nil {
						t.Fatal(err)
					}
					if config.Autoinstall.Storage.Layout.Password != passphrase || config.Autoinstall.Storage.Layout.Match["path"] != "/dev/vda" {
						t.Fatal("ARM adaptation altered the passphrase or encrypted root disk")
					}
					if len(config.Autoinstall.Commands) != 1 || len(config.Autoinstall.Commands[0]) != 8 {
						t.Fatal("missing ARM installed-root provisioning")
					}
					script = config.Autoinstall.Commands[0][7]
				} else {
					text := string(recipe)
					if !strings.Contains(text, "--passphrase="+nativeQuote(passphrase)+"\n") || !strings.Contains(text, "ignoredisk --only-use=vda\n") {
						t.Fatal("ARM adaptation altered the passphrase or encrypted root disk")
					}
					_, post, ok := strings.Cut(text, "%post --erroronfail --interpreter=/bin/sh\n")
					if !ok {
						t.Fatal("missing ARM installed-root provisioning")
					}
					script = strings.TrimSuffix(post, "%end\n")
					if desktop != "" || tpmBoot {
						if !strings.Contains(script, "/Everything/aarch64/os/") || !strings.Contains(script, "RPM-GPG-KEY-fedora-44-aarch64") {
							t.Fatal("ARM Fedora packages use the wrong repository or signing key path")
						}
					}
				}
				if !strings.Contains(script, "console=ttyAMA0,115200") || !strings.Contains(script, "GRUB_TERMINAL=\"console\"\n") {
					t.Fatal("ARM guest lacks PL011 kernel console and EFI GRUB console")
				}
				for _, unwanted := range []string{"ttyS0", "serial --unit", "GRUB_SERIAL_COMMAND", "/Everything/x86_64/", "RPM-GPG-KEY-fedora-44-x86_64"} {
					if strings.Contains(script, unwanted) {
						t.Errorf("ARM installed guest retained %q", unwanted)
					}
				}
				cmd := exec.Command("/bin/sh", "-n")
				cmd.Stdin = strings.NewReader(script)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("invalid ARM provisioning syntax: %v: %s", err, out)
				}
				alias, err := encryptedInstallerRecipeForMachine(distribution, passphrase, login, private, public, desktop, tpmBoot, "arm64")
				if err != nil || !bytes.Equal(recipe, alias) {
					t.Fatal("arm64 and aarch64 select different guest machines")
				}
			}
		}
		legacy, err := encryptedInstallerRecipeWithOptions(distribution, passphrase, login, private, public, "", false)
		if err != nil {
			t.Fatal(err)
		}
		amd64, err := encryptedInstallerRecipeForMachine(distribution, passphrase, login, private, public, "", false, "amd64")
		if err != nil || !bytes.Equal(legacy, amd64) {
			t.Fatal("existing x86 helper changed machine behavior")
		}
	}
	if _, err := encryptedInstallerRecipeForMachine("ubuntu", passphrase, login, private, public, "", false, "arm64;bad"); err == nil {
		t.Fatal("accepted architecture injection")
	}
}

func TestEncryptedInstallerARMGRUB(t *testing.T) {
	original := []byte("serial --unit=0 --speed=115200\nterminal_input console serial\nterminal_output gfxterm\nmenuentry 'vendor' {\nlinux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=Fedora console=ttyS0,115200n8 quiet\ninitrd /images/pxeboot/initrd.img\n}\n")
	for _, distribution := range []string{"ubuntu", "fedora"} {
		result, err := encryptedInstallerGRUBForMachine(original, distribution, "aarch64")
		if err != nil {
			t.Fatal(err)
		}
		text := string(result)
		for _, required := range []string{"terminal_input console\n", "terminal_output console\n", "console=ttyAMA0,115200", "linux /images/pxeboot/vmlinuz", "initrd /images/pxeboot/initrd.img", "inst.stage2=hd:LABEL=Fedora"} {
			if !strings.Contains(text, required) {
				t.Errorf("ARM boot recipe lacks %q", required)
			}
		}
		if strings.Contains(text, "ttyS0") || strings.Contains(text, "serial --unit") || strings.Contains(text, "console serial") {
			t.Fatal("ARM EFI boot retained x86 UART commands")
		}
	}
}
