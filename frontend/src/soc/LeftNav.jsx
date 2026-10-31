// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useState } from "react";
import { PRODUCT_NAME, VENDOR, NAV } from "../config";
import Icon from "../ui/Icon.jsx";
import Logo from "../ui/Logo.jsx";

function NavLeaf({ item, active, onSelect, nested }) {
  const on = active === item.key;
  return (
    <button onClick={() => onSelect(item.key)}
      className={`group w-full flex items-center gap-2.5 pr-2 h-8 rounded-md text-sm relative transition-colors ${
        nested ? "pl-9" : "pl-2.5"} ${on ? "text-text bg-brand/[0.09] font-medium" : "text-muted hover:text-text hover:bg-panel2"}`}>
      {on && <span className="absolute left-0 top-1.5 bottom-1.5 w-[2.5px] rounded-r bg-brand" />}
      {item.icon && <span className={on ? "text-brand" : "text-muted group-hover:text-text"}><Icon name={item.icon} /></span>}
      {nested && <span className={`w-1 h-1 rounded-full ${on ? "bg-brand" : "bg-edge2"}`} />}
      <span className="truncate">{item.label}</span>
    </button>
  );
}

function NavGroup({ item, active, onSelect }) {
  const containsActive = item.children.some((c) => c.key === active);
  const [open, setOpen] = useState(containsActive);
  const expanded = open || containsActive;
  return (
    <li>
      <button onClick={() => setOpen((v) => !v)}
        className={`group w-full flex items-center gap-2.5 pl-2.5 pr-2 h-8 rounded-sm text-sm transition-colors ${
          containsActive ? "text-text" : "text-muted hover:text-text hover:bg-panel2/60"}`}>
        <span className={containsActive ? "text-brand" : "text-muted group-hover:text-text"}><Icon name={item.icon} /></span>
        <span className="truncate">{item.label}</span>
        <span className={`ml-auto text-faint transition-transform ${expanded ? "rotate-90" : ""}`}><Icon name="chevron" size={12} /></span>
      </button>
      {expanded && (
        <ul className="mt-0.5 space-y-0.5">
          {item.children.map((c) => (
            <li key={c.key}><NavLeaf item={c} active={active} onSelect={onSelect} nested /></li>
          ))}
        </ul>
      )}
    </li>
  );
}

export default function LeftNav({ active, onSelect }) {
  return (
    <nav className="w-52 shrink-0 bg-panel border-r border-edge flex flex-col">
      {/* Brand */}
      <div className="h-14 px-3 flex items-center gap-2.5 border-b border-edge">
        <Logo size={30} />
        <div className="leading-none">
          <div className="text-[16px] font-semibold tracking-tight text-text">{PRODUCT_NAME}</div>
          <div className="text-2xs text-muted tracking-wide">{VENDOR} · IT/OT SOC</div>
        </div>
      </div>

      <ul className="py-2 px-2 space-y-0.5 overflow-y-auto flex-1">
        {NAV.map((n) => (
          n.children
            ? <NavGroup key={n.group || n.label} item={n} active={active} onSelect={onSelect} />
            : <li key={n.key}><NavLeaf item={n} active={active} onSelect={onSelect} /></li>
        ))}
      </ul>

      <div className="mt-auto p-3 border-t border-edge space-y-1.5">
        <a href="/range" className="flex items-center gap-1.5 text-xs text-muted hover:text-brand transition-colors">
          <Icon name="telemetry" size={13} /> Range Console →
        </a>
        <div className="flex items-center gap-1.5 text-2xs text-faint mono">
          <span className="dot dot-ok" /> Zeek + ICSNPP · live
        </div>
      </div>
    </nav>
  );
}
