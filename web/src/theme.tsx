import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

export type Theme = "light" | "dark";

const THEME_KEY = "wharf.theme";

function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch {
    // 读不到就跟随系统。
  }
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

const Ctx = createContext<{ theme: Theme; toggle: () => void }>({ theme: "light", toggle: () => {} });

export const useTheme = () => useContext(Ctx);

/** 深浅色：默认跟随系统，切换过就记在浏览器里。 */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    document.documentElement.style.colorScheme = theme;
  }, [theme]);
  const toggle = () =>
    setTheme((t) => {
      const next = t === "light" ? "dark" : "light";
      try {
        localStorage.setItem(THEME_KEY, next);
      } catch {
        // 只在本次页面里生效。
      }
      return next;
    });
  return <Ctx.Provider value={{ theme, toggle }}>{children}</Ctx.Provider>;
}
