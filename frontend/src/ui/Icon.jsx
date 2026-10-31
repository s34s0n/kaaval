// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Inline stroke SVG icons — no icon library, no emoji. 16px, currentColor.
const PATHS = {
  incidents: <path d="M8 1.5 1.5 13h13L8 1.5Z M8 6v3 M8 11h.01" />,
  telemetry: <path d="M1.5 8h3l2-5 3 10 2-5h3" />,
  detections: <><circle cx="7" cy="7" r="4.5" /><path d="M10.5 10.5 14.5 14.5" /></>,
  assets: <><rect x="2" y="2.5" width="12" height="4" /><rect x="2" y="9.5" width="12" height="4" /></>,
  settings: <><circle cx="8" cy="8" r="2" /><path d="M8 1v2 M8 13v2 M1 8h2 M13 8h2 M3 3l1.5 1.5 M11.5 11.5 13 13 M13 3l-1.5 1.5 M4.5 11.5 3 13" /></>,
  pivot: <path d="M2 5h5v6 M14 5H9v6 M7 11h2" />,
  bolt: <path d="M9 1 3 9h4l-1 6 6-8H8l1-6Z" />,
  shield: <path d="M8 1.5 13.5 4v4c0 3.5-2.5 5.5-5.5 6.5C5 13.5 2.5 11.5 2.5 8V4L8 1.5Z" />,
  chevron: <path d="M6 4l4 4-4 4" />,
  overview: <><rect x="2" y="2" width="5" height="5" /><rect x="9" y="2" width="5" height="5" /><rect x="2" y="9" width="5" height="5" /><rect x="9" y="9" width="5" height="5" /></>,
  report: <><rect x="3" y="1.5" width="10" height="13" /><path d="M5.5 5h5 M5.5 8h5 M5.5 11h3" /></>,
  network: <><circle cx="3.2" cy="3.4" r="1.5" /><circle cx="12.8" cy="4.2" r="1.5" /><circle cx="8" cy="12.6" r="1.5" /><path d="M4.6 3.8 11.4 4.2 M3.7 4.7 7.3 11.2 M12.2 5.5 8.8 11.2" /></>,
  sun: <><circle cx="8" cy="8" r="3" /><path d="M8 1v1.6 M8 13.4V15 M1 8h1.6 M13.4 8H15 M3 3l1.1 1.1 M11.9 11.9 13 13 M13 3l-1.1 1.1 M4.1 11.9 3 13" /></>,
  moon: <path d="M13 9.4A5.5 5.5 0 0 1 6.6 3 5.5 5.5 0 1 0 13 9.4Z" />,
  reset: <path d="M13.2 8a5.2 5.2 0 1 1-1.5-3.7 M13.2 2.4V5.2H10.4" />,
  launch: <path d="M4 2.6v10.8l9-5.4-9-5.4Z" />,
  external: <><path d="M9 3h4v4" /><path d="M13 3 7.5 8.5" /><path d="M11 9.5V13H3V5h3.5" /></>,
};

export default function Icon({ name, size = 16, className = "" }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none"
      stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"
      strokeLinejoin="round" className={className} aria-hidden="true">
      {PATHS[name] || null}
    </svg>
  );
}
