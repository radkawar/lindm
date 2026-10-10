import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { createServer } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { chromium } from "playwright";

const exec = promisify(execFile);
const elementKey = "element-6066-11e4-a52e-4f735466cecf";

// Only observes DOM state. Actions always use browser input/element endpoints.
function locate(query) {
  const visible = (node) =>
    node.getClientRects().length > 0 && getComputedStyle(node).visibility !== "hidden";
  const normalize = (value) => value.replace(/\s+/g, " ").trim();
  let root = document;
  if (query.dialog) {
    root = [...document.querySelectorAll('[role="dialog"]')].find(visible);
    if (!root) return null;
  }
  let nodes;
  if (query.label) {
    const label = [...root.querySelectorAll("label")].find(
      (node) => visible(node) && normalize(node.textContent) === query.label,
    );
    nodes = label ? [label.control ?? label.querySelector("input,textarea,button")] : [];
    if (!nodes[0])
      nodes = [...root.querySelectorAll("[aria-label]")].filter(
        (node) => node.getAttribute("aria-label") === query.label,
      );
  } else {
    const selectors = {
      button: 'button,[role="button"]',
      link: 'a[href],[role="link"]',
      option: '[role="option"]',
      tab: '[role="tab"]',
      status: '[role="status"]',
      heading: 'h1,h2,h3,h4,[role="heading"]',
      menuitem: '[role="menuitem"]',
    };
    nodes = [...root.querySelectorAll(query.css ?? selectors[query.role] ?? "*")];
  }
  nodes = nodes.filter((node) => {
    if (!node || !visible(node)) return false;
    const text = normalize(node.innerText ?? node.textContent ?? "");
    if (query.text !== undefined && text !== query.text) return false;
    if (query.contains !== undefined && !text.includes(query.contains)) return false;
    if (query.enabled && (node.disabled || node.getAttribute("aria-disabled") === "true"))
      return false;
    return true;
  });
  if (query.first) return nodes[0] ?? null;
  if (nodes.length > 1) throw new Error("ambiguous_ui_locator");
  return nodes[0] ?? null;
}

export class UI {
  constructor(driver, timeoutMs) {
    this.driver = driver;
    this.timeoutMs = timeoutMs;
  }
  async wait(query) {
    const deadline = Date.now() + this.timeoutMs;
    while (Date.now() < deadline) {
      const element = await this.driver.find(query);
      if (element) return element;
      await delay(100);
    }
    throw new Error("ui_condition_timeout");
  }
  async click(query) {
    await this.driver.click(await this.wait({ ...query, enabled: true }));
  }
  async fill(query, value) {
    await this.driver.fill(await this.wait({ ...query, enabled: true }), value);
  }
  async value(query) {
    return this.driver.property(await this.wait(query), "value");
  }
  async text(query) {
    return this.driver.property(await this.wait(query), "innerText");
  }
  async select(label, text, dialog = false) {
    await this.click({ label, dialog });
    await this.click({ role: "option", text });
  }
  async nonemptyValue(query) {
    const deadline = Date.now() + this.timeoutMs;
    while (Date.now() < deadline) {
      const value = await this.value(query);
      if (value) return value;
      await delay(100);
    }
    throw new Error("empty_customer_commands");
  }
}

export class ChromiumDriver {
  async open(config) {
    this.browser = await chromium.launch({ headless: true, timeout: 30_000 });
    this.context = await this.browser.newContext({
      ignoreHTTPSErrors: config.ignoreHTTPSErrors === true,
      viewport: { width: 1440, height: 1000 },
    });
    this.page = await this.context.newPage();
    this.page.setDefaultTimeout(config.actionTimeoutMs ?? 30_000);
    this.metadata = {
      transport: "playwright-cdp",
      browserVersion: this.browser.version(),
      playwright: "1.64.0",
    };
  }
  async authenticator(credentials = []) {
    this.cdp = await this.context.newCDPSession(this.page);
    await this.cdp.send("WebAuthn.enable");
    const result = await this.cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    this.authenticatorId = result.authenticatorId;
    for (const credential of credentials) {
      const copy = { ...credential };
      for (const field of ["credentialId", "privateKey", "userHandle"]) {
        if (copy[field]) copy[field] = Buffer.from(copy[field], "base64url").toString("base64");
      }
      await this.cdp.send("WebAuthn.addCredential", {
        authenticatorId: this.authenticatorId,
        credential: copy,
      });
    }
  }
  async credentials() {
    const { credentials } = await this.cdp.send("WebAuthn.getCredentials", {
      authenticatorId: this.authenticatorId,
    });
    return credentials.map((credential) => {
      const result = {};
      for (const field of [
        "credentialId",
        "privateKey",
        "userHandle",
        "rpId",
        "signCount",
        "isResidentCredential",
      ]) {
        if (credential[field] !== undefined) result[field] = credential[field];
      }
      for (const field of ["credentialId", "privateKey", "userHandle"]) {
        if (result[field])
          result[field] = Buffer.from(result[field], "base64").toString("base64url");
      }
      return result;
    });
  }
  async find(query) {
    const handle = await this.page.evaluateHandle(locate, query);
    const element = handle.asElement();
    if (!element) await handle.dispose();
    return element;
  }
  async click(element) {
    try {
      await element.click();
    } finally {
      await element.dispose();
    }
  }
  async fill(element, value) {
    try {
      await element.fill(value);
    } finally {
      await element.dispose();
    }
  }
  async property(element, name) {
    try {
      return await element.evaluate((node, key) => node[key], name);
    } finally {
      await element.dispose();
    }
  }
  async observe(fn, args) {
    return this.page.evaluate(fn, args);
  }
  async browserTask(fn, args) {
    return this.page.evaluate(fn, args);
  }
  async goto(url) {
    await this.page.goto(url, { waitUntil: "domcontentloaded" });
  }
  async screenshot() {
    return this.page.screenshot({ fullPage: true, timeout: 10_000 });
  }
  async close() {
    if (this.browser) await this.browser.close();
  }
}

async function unusedPort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return port;
}

// Firefox and WebKit use native W3C WebDriver, never Playwright's JS credentials shim.
export class WebDriver {
  async open(config) {
    this.engine = config.engine;
    this.timeoutMs = config.actionTimeoutMs ?? 30_000;
    const options = config.webDriver ?? {};
    const root = join(homedir(), ".local/share/lindm/acceptance-browsers");
    const binary =
      options.binary ??
      (config.engine === "firefox" ? join(root, "geckodriver-0.37.1") : "/usr/bin/WebKitWebDriver");
    // WebKitGTK's driver has no --version switch. Its package version is the
    // native driver version; the session separately reports browserVersion.
    const version =
      config.engine === "firefox"
        ? await exec(binary, ["--version"], { timeout: 10_000, maxBuffer: 16_384 })
        : await exec("dpkg-query", ["-W", "-f=${Version}", "webkit2gtk-driver"], {
            timeout: 10_000,
            maxBuffer: 16_384,
          });
    this.metadata = {
      transport: "w3c-webdriver",
      driverVersion: version.stdout.trim(),
      driverBinary: binary,
    };
    if (config.engine === "firefox" && !/^geckodriver 0\.37\.1\b/.test(version.stdout)) {
      throw new Error("geckodriver_0_37_1_required");
    }
    const port = await unusedPort();
    this.origin = `http://127.0.0.1:${port}`;
    const driverArgs = [...(options.args ?? []), `--port=${port}`];
    const executable = config.engine === "webkit" ? (options.xvfbBinary ?? "xvfb-run") : binary;
    const args =
      config.engine === "webkit"
        ? [
            "--auto-servernum",
            "--server-args=-screen 0 1440x1000x24 -nolisten tcp",
            binary,
            ...driverArgs,
          ]
        : driverArgs;
    this.process = spawn(executable, args, { stdio: "ignore", detached: true });
    let spawnError;
    this.process.once("error", (error) => {
      spawnError = error;
    });
    const deadline = Date.now() + 30_000;
    let ready = false;
    while (Date.now() < deadline) {
      if (spawnError || this.process.exitCode !== null) throw new Error("webdriver_start_failed");
      try {
        await this.request("GET", "/status", undefined, 1000);
        ready = true;
        break;
      } catch {
        await delay(100);
      }
    }
    if (!ready) throw new Error("webdriver_start_timeout");
    const browserOptions =
      config.engine === "firefox"
        ? {
            "moz:firefoxOptions": {
              args: ["-headless", ...(options.browserArgs ?? [])],
              binary: options.browserBinary ?? join(root, "firefox-157.0.1/firefox/firefox"),
              // Firefox dispatches to physical USB before its native test
              // token manager. Select the latter for WebDriver-created CTAP2
              // devices; this does not override any page credential API.
              prefs: {
                "security.webauth.webauthn_enable_usbtoken": false,
                "security.webauth.webauthn_enable_softtoken": true,
              },
            },
          }
        : {
            "webkitgtk:browserOptions": {
              args: options.browserArgs ?? [],
              ...(options.browserBinary ? { binary: options.browserBinary } : {}),
            },
          };
    const session = await this.request("POST", "/session", {
      capabilities: {
        alwaysMatch: {
          browserName: config.engine === "firefox" ? "firefox" : "MiniBrowser",
          acceptInsecureCerts: config.ignoreHTTPSErrors === true,
          ...browserOptions,
        },
      },
    });
    this.sessionId = session.sessionId;
    this.metadata.browserVersion = session.capabilities.browserVersion;
    if (config.engine === "firefox" && Number.parseInt(this.metadata.browserVersion, 10) < 152) {
      throw new Error("firefox_152_or_newer_required");
    }
    await this.command("POST", "/timeouts", {
      implicit: 0,
      pageLoad: this.timeoutMs,
      script: this.timeoutMs,
    });
    await this.command("POST", "/window/rect", { width: 1440, height: 1000 });
  }
  async request(method, path, body, timeout = this.timeoutMs) {
    const response = await fetch(this.origin + path, {
      method,
      headers: { "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(timeout),
    });
    const chunks = [];
    let bytes = 0;
    for await (const chunk of response.body) {
      bytes += chunk.length;
      if (bytes > 32 * 1024 * 1024) throw new Error("webdriver_response_too_large");
      chunks.push(chunk);
    }
    const payload = JSON.parse(Buffer.concat(chunks, bytes).toString("utf8"));
    if (!response.ok || payload.value?.error) {
      const error = new Error("webdriver_command_failed");
      error.code = payload.value?.error ?? `http_${response.status}`;
      throw error;
    }
    return payload.value;
  }
  async command(method, path, body) {
    return this.request(method, `/session/${this.sessionId}${path}`, body);
  }
  async authenticator(credentials = []) {
    try {
      this.authenticatorId = await this.command("POST", "/webauthn/authenticator", {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserConsenting: true,
        isUserVerified: true,
      });
    } catch (cause) {
      throw new Error("native_virtual_authenticator_unavailable", { cause });
    }
    for (const credential of credentials) {
      await this.command(
        "POST",
        `/webauthn/authenticator/${this.authenticatorId}/credential`,
        credential,
      );
    }
  }
  async credentials() {
    return this.command("GET", `/webauthn/authenticator/${this.authenticatorId}/credentials`);
  }
  async find(query) {
    return this.observe(locate, query);
  }
  async click(element) {
    await this.command("POST", `/element/${element[elementKey]}/click`, {});
  }
  async fill(element, text) {
    await this.command("POST", `/element/${element[elementKey]}/clear`, {});
    await this.command("POST", `/element/${element[elementKey]}/value`, { text });
  }
  async property(element, name) {
    return this.command("GET", `/element/${element[elementKey]}/property/${name}`);
  }
  async observe(fn, args) {
    return this.command("POST", "/execute/sync", {
      script: `return (${fn.toString()})(arguments[0]);`,
      args: [args ?? null],
    });
  }
  async browserTask(fn, args) {
    const result = await this.command("POST", "/execute/async", {
      script: `const done = arguments[arguments.length - 1];
        Promise.resolve().then(() => (${fn.toString()})(arguments[0]))
          .then(value => done({ ok: true, value }),
            () => done({ ok: false }));`,
      args: [args ?? null],
    });
    if (!result?.ok) throw new Error("browser_task_failed");
    return result.value;
  }
  async goto(url) {
    await this.command("POST", "/url", { url });
  }
  async screenshot() {
    return Buffer.from(await this.command("GET", "/screenshot"), "base64");
  }
  async close() {
    try {
      if (this.sessionId)
        await this.request("DELETE", `/session/${this.sessionId}`, undefined, 10_000);
    } finally {
      const child = this.process;
      if (child?.pid) {
        const signalGroup = (signal) => {
          try {
            process.kill(-child.pid, signal);
            return true;
          } catch (error) {
            if (error.code !== "ESRCH") throw error;
            return false;
          }
        };
        const reaped = () => child.exitCode !== null || child.signalCode !== null;
        const waitForCleanup = async (timeoutMs) => {
          const deadline = Date.now() + timeoutMs;
          while (Date.now() < deadline) {
            // The driver's leader may exit before its browser/Xvfb children.
            // Require both the actual child exit and disappearance of its group.
            if (reaped() && !signalGroup(0)) return true;
            await delay(50);
          }
          return reaped() && !signalGroup(0);
        };
        signalGroup("SIGTERM");
        if (!(await waitForCleanup(5_000))) {
          signalGroup("SIGKILL");
          if (!(await waitForCleanup(5_000))) throw new Error("webdriver_process_group_not_reaped");
        }
      }
    }
  }
}
