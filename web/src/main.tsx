import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { createRoot } from "react-dom/client";
import { queryClient } from "./app/query";
import { router } from "./app/router";
import "./styles/globals.css";

const colorScheme = window.matchMedia("(prefers-color-scheme: dark)");
document.documentElement.classList.toggle("dark", colorScheme.matches);
colorScheme.addEventListener("change", (event) => {
  document.documentElement.classList.toggle("dark", event.matches);
});

const root = document.querySelector("#root");
if (root === null) throw new Error("Console root element is missing.");

createRoot(root).render(
  <QueryClientProvider client={queryClient}>
    <RouterProvider router={router} />
  </QueryClientProvider>,
);
