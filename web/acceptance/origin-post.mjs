// This diagnostic is separate from authentication qualification. It deliberately
// submits an invalid, secret-free message through the console's own loaded auth
// client. It neither removes the UI capability guard nor installs a credential API.
export async function originPost(ui, config) {
  await ui.wait({ label: "Username" });
  const observation = await ui.driver.browserTask(
    async ({ origin }) => {
      const documentResponse = await fetch(location.href, {
        mode: "same-origin",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      const headers = {
        contentSecurityPolicy: documentResponse.headers.get("content-security-policy"),
        referrerPolicy: documentResponse.headers.get("referrer-policy"),
      };
      await documentResponse.body?.cancel();
      const modules = performance
        .getEntriesByType("resource")
        .map((entry) => new URL(entry.name))
        .filter(
          (url) => url.origin === origin && /^\/assets\/local-api-[^/]+\.js$/.test(url.pathname),
        );
      const uniqueModules = [...new Set(modules.map((url) => url.href))];
      if (uniqueModules.length !== 1)
        return { ...headers, failure: "loaded_auth_client_module_not_unique" };
      const moduleURL = uniqueModules[0];
      const client = await import(moduleURL);
      if (typeof client.beginLogin !== "function")
        return { ...headers, moduleURL, failure: "named_auth_client_export_missing" };
      let responseStatus = 0;
      let unexpectedlyAccepted = false;
      const started = performance.now();
      try {
        await client.beginLogin(
          {
            $typeName: "lindm.auth.v1.LocalLoginRequest",
            username: "",
            password: "",
            incidentReason: "",
          },
          AbortSignal.timeout(10_000),
        );
        unexpectedlyAccepted = true;
      } catch (error) {
        // The actual application client exposes status in this fixed, secret-free
        // error. Never retain arbitrary browser errors or authentication bodies.
        const match = /^Authentication request failed \((\d{3})\)\.$/.exec(error.rawMessage ?? "");
        if (match) responseStatus = Number(match[1]);
      }
      const timing = performance
        .getEntriesByType("resource")
        .find(
          (entry) =>
            entry.startTime >= started &&
            new URL(entry.name).pathname === "/auth/local/login/begin",
        );
      return {
        ...headers,
        documentStatus: documentResponse.status,
        expectedOrigin: origin,
        moduleURL,
        responseStatus,
        resourceTimingStatus: timing?.responseStatus ?? 0,
        requestObserved: !!timing,
        unexpectedlyAccepted,
        passkeyQualification: false,
      };
    },
    { origin: config.origin },
  );
  observation.passed =
    observation.documentStatus === 200 &&
    observation.referrerPolicy === "same-origin" &&
    observation.contentSecurityPolicy?.includes("connect-src 'self'") === true &&
    observation.responseStatus === 400 &&
    !observation.unexpectedlyAccepted;
  return observation;
}
