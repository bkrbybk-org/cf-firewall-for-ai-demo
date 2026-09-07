// Maps a category `iconKey` (see data.ts) to a lucide icon component.
import {
  ShieldCheck,
  Syringe,
  EyeOff,
  IdCard,
  Skull,
  Lock,
  Banknote,
  Vote,
  Smartphone,
  Layers,
  Bug,
  Megaphone,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react";

const ICONS: Record<string, LucideIcon> = {
  "shield-check": ShieldCheck,
  syringe: Syringe,
  "eye-off": EyeOff,
  "id-card": IdCard,
  skull: Skull,
  lock: Lock,
  banknote: Banknote,
  vote: Vote,
  smartphone: Smartphone,
  layers: Layers,
  bug: Bug,
  megaphone: Megaphone,
};

export function categoryIcon(key: string): LucideIcon {
  return ICONS[key] ?? ShieldAlert;
}
