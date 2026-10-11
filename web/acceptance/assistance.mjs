#!/usr/bin/env node
import { createInterface } from "node:readline";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { ChromiumDriver, UI } from "./drivers.mjs";
import { enroll, signIn } from "./journey.mjs";
import { privateDirectory, readPrivateJSON, writePrivate } from "./private-files.mjs";
import { startupFailure, startupStage } from "./assistance-startup.mjs";

// Line-oriented private control protocol for `lab vm assistance`
// (internal/vmlab/vm_assistance_browser_linux.go). Each stdin line is one JSON
// command and each stdout line is exactly one JSON reply. The operator signs
// in through the real console UI; replies and screenshots never carry
// credentials and browser exceptions are reduced to stable codes.
process.umask(0o077);

const SURFACE = '[aria-label^="Remote screen"]';
let config;
let driver;
let ui;
let startStage = "configuration";

function starting(stage) {
  startStage = stage;
  startupStage(stage);
}

// Observe the console's own peer. Split lanes additionally restrict TURN URLs
// to the SSH-forwarded endpoint to model a browser outside the controller LAN;
// the console's relay-only policy and all other RTC configuration stay intact.
function observePeers(forwardedTURNURL) {
  const Native = window.RTCPeerConnection;
  const peers = [];
  Object.defineProperty(window, "__lindmLabPeers", { value: peers });
  window.RTCPeerConnection = class extends Native {
    constructor(configuration, ...rest) {
      if (forwardedTURNURL) {
        configuration = {
          ...configuration,
          iceServers: (configuration?.iceServers ?? []).flatMap((server) => {
            const urls = [server.urls].flat().filter((url) => url === forwardedTURNURL);
            return urls.length ? [{ ...server, urls }] : [];
          }),
        };
      }
      super(configuration, ...rest);
      const record = {
        pc: this,
        policy: configuration?.iceTransportPolicy ?? "all",
        channels: [],
      };
      peers.push(record);
      this.addEventListener("datachannel", (event) => record.channels.push(event.channel.label));
    }
  };
}

async function observeMedia(surface) {
  const video = document.querySelector(`${surface} video`);
  const record = window.__lindmLabPeers?.at(-1);
  const result = {
    videoWidth: video?.videoWidth ?? 0,
    videoHeight: video?.videoHeight ?? 0,
    decodedFrames: video?.webkitDecodedFrameCount ?? 0,
    framesDecoded: 0,
    connectionState: record?.pc.connectionState ?? "",
    transportPolicy: record?.policy ?? "",
    remoteApplication: /^m=application /m.test(record?.pc.remoteDescription?.sdp ?? ""),
    dataChannels: [...(record?.channels ?? [])],
    localCandidateType: "",
    localRelayProtocol: "",
    localCandidateURL: "",
    remoteCandidateType: "",
    controlButton: [...document.querySelectorAll("button")].some((node) =>
      /^(Take control|Release control)$/.test(node.innerText.trim()),
    ),
  };
  if (!record || record.pc.connectionState === "closed") return result;
  const stats = await record.pc.getStats();
  let pair;
  stats.forEach((report) => {
    if (report.type === "inbound-rtp" && report.kind === "video")
      result.framesDecoded = report.framesDecoded ?? 0;
    if (report.type === "transport" && report.selectedCandidatePairId)
      pair = stats.get(report.selectedCandidatePairId);
  });
  if (pair) {
    result.localCandidateType = stats.get(pair.localCandidateId)?.candidateType ?? "";
    result.remoteCandidateType = stats.get(pair.remoteCandidateId)?.candidateType ?? "";
    result.localRelayProtocol = stats.get(pair.localCandidateId)?.relayProtocol ?? "";
    result.localCandidateURL = stats.get(pair.localCandidateId)?.url ?? "";
  }
  return result;
}

async function until(check, timeoutMs, code) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await delay(200);
  }
  throw new Error(code);
}

function timeout(args) {
  const value = args.timeoutMs ?? config.actionTimeoutMs;
  if (!Number.isInteger(value) || value < 1000 || value > 600_000)
    throw new Error("invalid_deadline");
  return value;
}

const commands = {
  async start() {
    starting("chromium_launch");
    driver = new ChromiumDriver();
    await driver.open(config);
    starting("browser_setup");
    await driver.context.addInitScript(observePeers, config.forwardedTurnUrl ?? "");
    ui = new UI(driver, config.actionTimeoutMs);
    starting("navigation");
    await driver.goto(config.origin);
    starting("authenticator");
    await driver.authenticator([]);
    starting("enrollment");
    await enroll(ui, config);
    starting("sign_in");
    await signIn(ui, config);
    return { engine: "chromium", version: driver.metadata.browserVersion };
  },
  async request(args) {
    if (!/^[0-9a-f-]{36}$/.test(args.deviceId ?? "")) throw new Error("invalid_device");
    const label = { view: "View screen", control: "View and request control" }[args.mode];
    if (!label) throw new Error("invalid_mode");
    await driver.goto(`${config.origin}/devices/${args.deviceId}`);
    await ui.click({ role: "tab", text: "Actions" });
    await ui.select("Mode", label);
    await ui.fill({ label: "Maximum duration (minutes, 1 to 30)" }, String(args.minutes));
    await ui.fill({ label: "Reason (shown to the local user and audited)" }, args.reason);
    await ui.click({ role: "button", text: "Request remote assistance" });
    const match = await until(
      () => /\/assistance\/([0-9a-f-]{36})$/.exec(new URL(driver.page.url()).pathname),
      config.actionTimeoutMs,
      "viewer_navigation_timeout",
    );
    return { sessionId: match[1] };
  },
  async media(args) {
    const minFrames = args.minFrames ?? 1;
    let last;
    try {
      return await until(
        async () => {
          last = await driver.page.evaluate(observeMedia, SURFACE);
          return last.videoWidth > 0 && last.decodedFrames >= minFrames ? last : null;
        },
        timeout(args),
        "video_frames_timeout",
      );
    } catch (error) {
      if (last) error.observation = last;
      throw error;
    }
  },
  async observe() {
    return driver.page.evaluate(observeMedia, SURFACE);
  },
  async control() {
    await ui.click({ role: "button", text: "Take control" });
    await ui.wait({ role: "button", text: "Release control" });
    return {};
  },
  async click(args) {
    const { x, y } = args;
    if (!(x >= 0 && x <= 1 && y >= 0 && y <= 1)) throw new Error("invalid_point");
    const box = await driver.page.evaluate((surface) => {
      const video = document.querySelector(`${surface} video`);
      const rect = video.getBoundingClientRect();
      return {
        x: rect.x,
        y: rect.y,
        width: rect.width,
        height: rect.height,
        videoWidth: video.videoWidth,
        videoHeight: video.videoHeight,
      };
    }, SURFACE);
    if (!box.videoWidth || !box.videoHeight) throw new Error("video_not_rendered");
    // object-contain letterboxes the frame inside the element.
    const scale = Math.min(box.width / box.videoWidth, box.height / box.videoHeight);
    const left = box.x + (box.width - box.videoWidth * scale) / 2;
    const top = box.y + (box.height - box.videoHeight * scale) / 2;
    await driver.page.mouse.click(
      left + x * box.videoWidth * scale,
      top + y * box.videoHeight * scale,
    );
    return {};
  },
  async type(args) {
    if (!/^[a-z0-9]{1,64}$/.test(args.text ?? "")) throw new Error("invalid_text");
    const focused = await driver.page.evaluate(
      (surface) => document.activeElement === document.querySelector(surface),
      SURFACE,
    );
    if (!focused) throw new Error("remote_surface_not_focused");
    await driver.page.keyboard.type(args.text, { delay: 40 });
    if (args.enter) await driver.page.keyboard.press("Enter");
    return {};
  },
  async stop() {
    await ui.click({ role: "button", text: "Stop session" });
    return {};
  },
  async ended(args) {
    // The viewer states the end cause in the paragraph after its
    // "Why this session ended" heading.
    const cause = await until(
      () =>
        driver.page.evaluate(() => {
          const heading = [...document.querySelectorAll("h2")].find(
            (node) => node.textContent.trim() === "Why this session ended",
          );
          return heading?.nextElementSibling?.innerText.trim() ?? "";
        }),
      timeout(args),
      "console_end_cause_timeout",
    );
    return { cause };
  },
  async screenshot(args) {
    if (!/^[a-z0-9-]{1,80}\.png$/.test(args.name ?? "")) throw new Error("invalid_screenshot_name");
    const path = join(config.evidenceDirectory, args.name);
    await writePrivate(path, await driver.screenshot());
    return { path: args.name };
  },
  async leave(args) {
    if (!/^[0-9a-f-]{36}$/.test(args.deviceId ?? "")) throw new Error("invalid_device");
    await driver.goto(`${config.origin}/devices/${args.deviceId}`);
    return {};
  },
};

function failure(error) {
  return {
    code: /^[a-z][a-z0-9_]+$/.test(error?.message ?? "") ? error.message : "browser_command_failed",
    errorType: error?.name ?? "Error",
    ...(error?.observation ? { observation: error.observation } : {}),
  };
}

function reply(value) {
  process.stdout.write(JSON.stringify(value) + "\n");
}

starting("configuration");
try {
  if (process.argv.length !== 3) throw new Error("private_config_path_required");
  config = await readPrivateJSON(resolve(process.argv[2]));
  for (const key of ["origin", "username", "password", "enrollmentSecret", "evidenceDirectory"]) {
    if (typeof config[key] !== "string" || !config[key])
      throw new Error("required_configuration_missing");
  }
  const origin = new URL(config.origin);
  if (origin.protocol !== "https:" || origin.origin !== config.origin)
    throw new Error("https_origin_required");
  config.evidenceDirectory = resolve(config.evidenceDirectory);
  await privateDirectory(config.evidenceDirectory);
  config.actionTimeoutMs ??= 30_000;
  config.ignoreHTTPSErrors = true; // Owned fixture CA only; origin/CSRF checks stay intact.
  // A remote console behind an SSH -L forward reaches the relay only with TURN
  // over TCP; Chromium's own policy reproduces that without touching the page.
  if (config.turnTcpOnly !== undefined && typeof config.turnTcpOnly !== "boolean")
    throw new Error("invalid_turn_tcp_only");
  config.browserArgs = config.turnTcpOnly
    ? ["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]
    : [];
} catch (error) {
  await new Promise((done) =>
    process.stdout.write(
      JSON.stringify({ id: 0, ok: false, error: startupFailure(error, startStage) }) + "\n",
      done,
    ),
  );
  process.exit(1);
}

let closing = false;
const shutdown = async () => {
  if (closing) return;
  closing = true;
  try {
    if (driver) await driver.close();
  } finally {
    process.exit(0);
  }
};
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    reply({ id: 0, ok: false, error: { code: "invalid_command" } });
    continue;
  }
  if (request.op === "close") break;
  const command = Object.hasOwn(commands, request.op) ? commands[request.op] : null;
  if (!command) {
    reply({ id: request.id, ok: false, error: { code: "unknown_command" } });
    continue;
  }
  try {
    reply({ id: request.id, ok: true, result: await command(request.args ?? {}) });
  } catch (error) {
    reply({
      id: request.id,
      ok: false,
      error: request.op === "start" ? startupFailure(error, startStage) : failure(error),
    });
  }
}
await shutdown();
