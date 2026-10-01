// Shared route tab strip — the second row of the header on every page.
// NavLink gives the active-page state for free; `end` keeps "/" from matching
// every route.
import { NavLink } from 'react-router-dom';
import {
  BarChart3,
  ClipboardCheck,
  ExternalLink,
  FileCode2,
  ShieldPlus,
  ShieldCheck,
  Swords,
  type LucideIcon,
} from 'lucide-react';

const TABS: { to: string; label: string; icon: LucideIcon; end?: boolean }[] = [
  { to: '/', label: 'AI Guardrails Demo', icon: ShieldCheck, end: true },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/redteam', label: 'Red Team', icon: Swords },
  { to: '/compliance', label: 'Compliance', icon: ClipboardCheck },
  { to: '/guardrails', label: 'Guardrails', icon: ShieldPlus },
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
      {/* A plain <a>, not a NavLink: /api-docs/ is a static page served next to the
          SPA, and the router would swallow it as an unknown client route. New tab,
          so opening the reference never loses a chat or a red-team run in progress. */}
      <a
        href='/api-docs/'
        target='_blank'
        rel='noopener noreferrer'
        title='OpenAPI 3.0 reference (Swagger UI) — the same document API Shield accepts'
        className='ml-auto flex shrink-0 items-center gap-1.5 whitespace-nowrap border-b-2 border-transparent px-3 py-2 text-[12.5px] text-muted transition hover:border-line-strong hover:text-text'>
        <FileCode2 size={14} /> API docs <ExternalLink size={11} />
      </a>
    </nav>
  );
}
