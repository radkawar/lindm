// Real seeded capability policies and executor reports (loadlab demo agents).
// Editors are opened and reviewed for their consequence text, never saved.
const devices = [
  // Unavailable: an unrecognized vendor key, with blocked packages, an existing
  // local group and the account that depends on it.
  {
    hostname: "ubuntu-ws-02",
    expect: [
      "Unavailable",
      "isn't one lindm recognizes",
      "already exists on the device",
      "An item this depends on needs attention",
    ],
  },
  // Set locally in executor.json.
  { hostname: "ubuntu-srv-04", expect: ["Set locally"] },
  // An agent older than capability policies.
  { hostname: "rhel-srv-05", expect: ["hasn't reported its capabilities"] },
  // A profile service with no systemd unit on the device; also a long hostname.
  {
    hostname: "fedora-ci-gpu-runner-0042.build-farm.eu-central-1.lab.example.internal",
    expect: ["isn't installed on the device"],
  },
];

export async function reviewCapabilities({
  pages,
  combos,
  config,
  screenshot,
  axe,
  probe,
  settle,
}) {
  const results = [];
  const ids = new Map((config.demo?.Devices ?? []).map((device) => [device.Hostname, device.ID]));
  for (const [index, { theme, viewport }] of combos.entries()) {
    const page = pages[index];
    const capture = async (route, url, variant, prefix, open) => {
      const entry = {
        route,
        url,
        variant,
        theme,
        viewport: viewport.name,
        size: `${viewport.width}x${viewport.height}`,
        passed: false,
        screenshots: {},
        checks: { contract: { findings: [] } },
      };
      const fail = (message) => entry.checks.contract.findings.push({ message, elements: [] });
      try {
        await page.goto(`${config.origin}${url}`);
        await settle(page);
        await open(fail);
        await settle(page);
        await page.evaluate(() => window.scrollTo(0, 0));
        entry.screenshots.full = await screenshot(page, `${prefix}-full.png`, true);
        const violations = await axe(page, null);
        entry.checks.axe = {
          violations,
          findings: violations
            .filter((item) => item.blocking)
            .map((item) => ({
              message: `${item.id} (${item.impact}): ${item.help}`,
              elements: item.nodes.map((node) => node.target),
            })),
        };
        entry.checks.layout = {
          findings: await probe(page, "layout", viewport.name === "desktop"),
        };
        entry.checks.copy = { findings: await probe(page, "copy") };
      } catch (error) {
        fail(`${variant} review failed: ${error.message}`);
        entry.screenshots.full = await screenshot(page, `${prefix}-failure.png`, true);
      }
      entry.passed = Object.values(entry.checks).every((check) => check.findings.length === 0);
      results.push(entry);
    };
    const suffix = `${theme}-${viewport.name}`;
    await capture(
      "/settings/capabilities",
      "/settings/capabilities",
      "Edit all devices",
      `settings-capabilities-edit-all-${suffix}`,
      async (fail) => {
        await page.getByRole("button", { name: "Edit all devices", exact: true }).click();
        const form = page.getByRole("form", { name: "Edit capabilities for all devices" });
        await form.waitFor();
        if (
          (await form.getByRole("group", { name: "Firewall settings for all devices" }).count()) !==
          1
        )
          fail("The all-devices editor omits the firewall settings");
        await form.getByRole("button", { name: "Add endpoint", exact: true }).click();
        await form.getByLabel("IP address", { exact: true }).fill("192.0.2.10");
        await countsDevices(form, fail);
        const text = await form.innerText();
        for (const expected of ["What happens when you save", "a connectivity check"])
          if (!text.includes(expected)) fail(`The all-devices editor omits "${expected}"`);
      },
    );
    await capture(
      "/settings/capabilities",
      "/settings/capabilities",
      "Edit Finance",
      `settings-capabilities-edit-group-${suffix}`,
      async (fail) => {
        await page.getByRole("button", { name: "Edit Finance", exact: true }).click();
        const form = page.getByRole("form", { name: "Edit capabilities for Finance" });
        await form.waitFor();
        await form.getByRole("checkbox", { name: "Kernel settings" }).check();
        await form
          .getByRole("textbox", { name: /^Kernel parameters lindm may set/ })
          .fill("vm.swappiness");
        await countsDevices(form, fail);
        const text = await form.innerText();
        if (!/turns on Kernel settings/.test(text) || !text.includes("device group Finance"))
          fail("The group editor's consequence review does not name the change and its group");
      },
    );
    for (const { hostname, expect } of devices) {
      const id = ids.get(hostname);
      if (!id) {
        results.push({
          route: "/devices/$deviceId",
          url: "",
          variant: `Services ${hostname}`,
          theme,
          viewport: viewport.name,
          passed: false,
          screenshots: {},
          checks: {
            contract: { findings: [{ message: `Seed has no ${hostname}`, elements: [] }] },
          },
        });
        continue;
      }
      await capture(
        "/devices/$deviceId",
        `/devices/${id}?tab=resources`,
        `Services ${hostname}`,
        // Edit-sheet screenshot names allow only [a-z0-9-].
        `device-services-${hostname.replace(/[^a-z0-9]+/g, "-")}-${suffix}`,
        async (fail) => {
          const card = page
            .locator("section, div")
            .filter({ has: page.getByRole("heading", { name: "Management capabilities" }) })
            .last();
          await card.waitFor();
          const text = await page.locator("main").innerText();
          for (const expected of expect)
            if (!text.includes(expected)) fail(`${hostname} Services tab omits "${expected}"`);
        },
      );
    }
  }
  return results;
}

// The consequence review states the blast radius as a count once it is known.
async function countsDevices(form, fail) {
  try {
    await form
      .getByText(/\(\d+ devices? now\)/)
      .first()
      .waitFor({ timeout: 15_000 });
  } catch {
    fail("The consequence review does not say how many devices the change reaches");
  }
}
