import { create } from "zustand"

export type Theme = "dark" | "light"
const STORAGE_KEY = "trishul-theme"

function apply(theme: Theme) {
  const root = document.documentElement
  root.classList.toggle("dark", theme === "dark")
  root.setAttribute("data-theme", theme)
}

// index.html has already applied the saved theme before first paint; read it back.
const initial: Theme = document.documentElement.classList.contains("dark") ? "dark" : "light"

interface ThemeState {
  theme: Theme
  setTheme: (theme: Theme) => void
  toggle: () => void
}

export const useThemeStore = create<ThemeState>((set, get) => ({
  theme: initial,
  setTheme: (theme) => {
    apply(theme)
    try {
      localStorage.setItem(STORAGE_KEY, theme)
    } catch {
      // Storage blocked (private window etc.): theme still applies for this session.
    }
    set({ theme })
  },
  toggle: () => get().setTheme(get().theme === "dark" ? "light" : "dark"),
}))
