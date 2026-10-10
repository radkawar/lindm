import { MoonIcon, SunIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";

export function ThemeToggle() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    document.documentElement.style.colorScheme = dark ? "dark" : "light";
    try {
      localStorage.setItem("lindm-theme", dark ? "dark" : "light");
    } catch {
      // Theme remains usable when browser storage is disabled.
    }
  }, [dark]);
  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
      onClick={() => setDark(!dark)}
    >
      {dark ? <SunIcon /> : <MoonIcon />}
    </Button>
  );
}
