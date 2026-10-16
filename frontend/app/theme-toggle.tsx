"use client";

import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";

export default function ThemeToggle() {
  const [theme, setTheme] = useState<"light" | "dark" | null>(null);
  useEffect(() => {
    const sync = () => setTheme(document.documentElement.dataset.theme === "light" ? "light" : "dark");
    sync();
    const observer = new MutationObserver(sync);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => observer.disconnect();
  }, []);
  function toggle() {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("csg-theme", next); } catch { /* Theme still works when storage is unavailable. */ }
    setTheme(next);
  }
  return <button type="button" className="theme-toggle" disabled={!theme} onClick={toggle}
    aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
    title={theme === "dark" ? "Light mode" : "Dark mode"}>
    {theme === "light" ? <Moon size={17}/> : <Sun size={17}/>}
    <span>{theme === "light" ? "Dark" : "Light"}</span>
  </button>;
}
