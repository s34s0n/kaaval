// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// The single product-name constant.
export const PRODUCT_NAME = "Kaaval";
export const VENDOR = "Traboda";

export const api = (path) => `/api${path}`;
export const WS_URL = (() => {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}`;
})();

// SOC left-nav (icons are keys into src/ui/Icon.jsx — inline SVG, no emoji).
// Items with `children` render as a collapsible group; every key maps to a view.
export const NAV = [
  { key: "overview", label: "Overview", icon: "overview" },
  { key: "incidents", label: "Incidents", icon: "incidents" },
  {
    label: "Network", icon: "network", group: "network",
    children: [
      { key: "purdue", label: "Purdue model" },
      { key: "net-protocols", label: "Protocols" },
      { key: "net-conversations", label: "Conversations" },
      { key: "net-dns", label: "DNS" },
      { key: "net-tls", label: "TLS / SSL" },
      { key: "net-ssh", label: "SSH sessions" },
      { key: "net-ot", label: "OT protocols" },
    ],
  },
  {
    label: "Detection", icon: "detections", group: "detection",
    children: [
      { key: "detections", label: "Rules" },
      { key: "det-coverage", label: "ATT&CK coverage" },
    ],
  },
  { key: "assets", label: "Asset discovery", icon: "assets" },
  { key: "compliance", label: "Compliance", icon: "report" },
  { key: "telemetry", label: "Raw telemetry", icon: "telemetry" },
  { key: "settings", label: "Settings", icon: "settings" },
];
