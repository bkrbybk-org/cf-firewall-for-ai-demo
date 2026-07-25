import { Moon, Sun } from "lucide-react";
import { useTheme } from "../hooks/useTheme";

export function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <button
      type="button"
      onClick={toggle}
      title={theme === "dark" ? "Switch to light" : "Switch to dark"}
      className="grid h-9 w-9 place-items-center rounded-full border border-line bg-surface-2 text-muted transition hover:border-accent hover:text-text active:scale-95"
    >
      {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
    </button>
  );
}
