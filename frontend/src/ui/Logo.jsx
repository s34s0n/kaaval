// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Kaaval mark — a guard shield enclosing an IT↔OT network triad (the product
// fuses IT and OT into one defended domain). Two-tone teal; reads on light + dark.
export default function Logo({ size = 30, className = "" }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className={className} aria-hidden="true">
      <defs>
        <linearGradient id="kvg" x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
          <stop stopColor="#34E0CC" />
          <stop offset="1" stopColor="#1B8E80" />
        </linearGradient>
      </defs>
      <path d="M16 2.6 27 6.6v7.6c0 7.2-4.8 11.6-11 13.8C9.8 25.8 5 21.4 5 14.2V6.6L16 2.6Z"
        fill="url(#kvg)" fillOpacity="0.14" stroke="url(#kvg)" strokeWidth="1.6" strokeLinejoin="round" />
      <path d="M11 12.6 21 12.6 M11 12.6 16 20 M21 12.6 16 20"
        stroke="url(#kvg)" strokeWidth="1.15" strokeOpacity="0.75" strokeLinecap="round" />
      <circle cx="11" cy="12.6" r="1.7" fill="#34E0CC" />
      <circle cx="21" cy="12.6" r="1.7" fill="#34E0CC" />
      <circle cx="16" cy="20" r="1.7" fill="#34E0CC" />
    </svg>
  );
}
