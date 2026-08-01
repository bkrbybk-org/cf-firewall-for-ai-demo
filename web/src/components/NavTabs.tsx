// Shared route tab strip — the second row of the header on every page.
// NavLink gives the active-page state for free; `end` keeps "/" from matching
// every route.
import { NavLink } from 'react-router-dom';
import {
  BarChart3,
  ClipboardCheck,
  ShieldCheck,
  Swords,
  type LucideIcon,
} from 'lucide-react';

const TABS: { to: string; label: string; icon: LucideIcon; end?: boolean }[] = [
  { to: '/', label: 'AI Guardrails Demo', icon: ShieldCheck, end: true },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/redteam', label: 'Red Team', icon: Swords },
  { to: '/compliance', label: 'Compliance', icon: ClipboardCheck },
];

export function NavTabs() {
  return (
    <nav className='flex gap-0.5 overflow-x-auto px-3'>
      {TABS.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          className={({ isActive }) =>
            `flex shrink-0 items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-[12.5px] transition ${
              isActive
                ? 'border-accent font-semibold text-accent'
                : 'border-transparent text-muted hover:border-line-strong hover:text-text'
            }`
          }>
          <Icon size={14} /> {label}
        </NavLink>
      ))}
    </nav>
  );
}
