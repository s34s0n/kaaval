// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { SocProvider, useSoc } from "./store.jsx";
import ErrorBoundary from "../ui/ErrorBoundary.jsx";
import LeftNav from "./LeftNav.jsx";
import TopBar from "./TopBar.jsx";
import Overview from "./Overview.jsx";
import IncidentWorkspace from "./IncidentWorkspace.jsx";
import Telemetry from "./Telemetry.jsx";
import Detections from "./Detections.jsx";
import Coverage from "./Coverage.jsx";
import Network from "./Network.jsx";
import Assets from "./Assets.jsx";
import Compliance from "./Compliance.jsx";
import Purdue from "./Purdue.jsx";
import { Settings } from "./sections.jsx";

const SECTIONS = {
  overview: Overview,
  incidents: IncidentWorkspace,
  telemetry: Telemetry,
  detections: Detections,
  "det-coverage": Coverage,
  assets: Assets,
  compliance: Compliance,
  purdue: Purdue,
  settings: Settings,
};

// Resolve a nav key to a rendered view (network sub-views share one component).
function renderSection(key) {
  if (key.startsWith("net-")) return <Network tab={key.slice(4)} />;
  const C = SECTIONS[key] || Overview;
  return <C />;
}

// Every selectable key (for validating the ?view= deep link).
const KEYS = new Set([...Object.keys(SECTIONS),
  "net-protocols", "net-conversations", "net-dns", "net-tls", "net-ssh", "net-ot"]);

// "Backend unreachable" banner — only after a short grace period, so a sub-second
// WS reconnect (or initial page load) doesn't flash a scary red bar. Distinguishes
// "feed lost" from a healthy-but-quiet baseline, which otherwise both read "—".
function ConnectionBanner() {
  const { connected } = useSoc();
  const [show, setShow] = useState(false);
  useEffect(() => {
    if (connected) { setShow(false); return; }
    const t = setTimeout(() => setShow(true), 2500);
    return () => clearTimeout(t);
  }, [connected]);
  return (
    <AnimatePresence>
      {show && (
        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 28, opacity: 1 }}
          exit={{ height: 0, opacity: 0 }}
          className="shrink-0 overflow-hidden bg-crit/15 border-b border-crit/40 flex items-center justify-center gap-2 text-crit text-2xs uppercase tracking-wider">
          <span className="w-1.5 h-1.5 rounded-full bg-crit animate-pulse" />
          Live feed lost — reconnecting to the Kaaval backend…
        </motion.div>
      )}
    </AnimatePresence>
  );
}

// IT containment makes the ews unreachable to the OT path — so a manual OT write
// is blackholed and (correctly) raises no incident. Surfacing it stops that from
// looking like a broken control.
function ContainmentBanner() {
  const { state } = useSoc();
  return (
    <AnimatePresence>
      {state?.ews_isolated && (
        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 28, opacity: 1 }}
          exit={{ height: 0, opacity: 0 }}
          className="shrink-0 overflow-hidden bg-warn/15 border-b border-warn/40 flex items-center justify-center gap-2 text-warn text-2xs uppercase tracking-wider">
          <span className="w-1.5 h-1.5 rounded-full bg-warn" />
          IT containment active — ews isolated from the OT path · manual OT writes are blocked until Reset
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function SocShell({ active, setActive }) {
  return (
    // min-width keeps the dense console intact on small screens (scroll, not squish);
    // transparent surfaces let the body's subtle ink/teal depth show through.
    <div className="h-full flex text-text min-w-[1040px] overflow-x-auto">
      <LeftNav active={active} onSelect={setActive} />
      <div className="flex-1 min-w-0 flex flex-col">
        <TopBar />
        <ConnectionBanner />
        <ContainmentBanner />
        {/* Per-section boundary: a crash in one view shows a recoverable panel
            instead of blanking the whole console. Keyed so it resets on nav. */}
        <main className="flex-1 min-h-0 overflow-hidden">
          <ErrorBoundary key={active}>
            {renderSection(active)}
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}

export default function SocApp() {
  const [active, setActive] = useState(() => {
    const v = new URLSearchParams(window.location.search).get("view");
    return v && KEYS.has(v) ? v : "overview";
  });
  return (
    <SocProvider>
      <SocShell active={active} setActive={setActive} />
    </SocProvider>
  );
}
