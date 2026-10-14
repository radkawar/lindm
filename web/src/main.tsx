// SPDX-License-Identifier: Apache-2.0

import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { createRoot } from "react-dom/client";
import { queryClient } from "./app/query";
import { router } from "./app/router";
import "./styles/globals.css";

let preferredTheme: string | null = null;
try {
  preferredTheme = localStorage.getItem("lindm-theme");
} catch {
  // System preference is available even when browser storage is disabled.
}
const dark =
  preferredTheme === "dark" ||
  (preferredTheme !== "light" && window.matchMedia("(prefers-color-scheme: dark)").matches);
document.documentElement.classList.toggle("dark", dark);
document.documentElement.style.colorScheme = dark ? "dark" : "light";

const root = document.querySelector("#root");
if (root === null) throw new Error("Console root element is missing.");

createRoot(root).render(
  <QueryClientProvider client={queryClient}>
    <RouterProvider router={router} />
  </QueryClientProvider>,
);
