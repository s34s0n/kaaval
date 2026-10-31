// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
/** Kaaval SOC design system — "Deep Ops": dark ink/navy operator console.
 *  BRAND (teal) drives all chrome/links/focus; AMBER is severity-only. Severity
 *  colors carry meaning, never decoration. */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      // Colors are theme variables (RGB channels) so light/dark swap via a single
      // `.light` class while the `/<alpha>` opacity utilities keep working.
      colors: {
        bg: "rgb(var(--bg) / <alpha-value>)",
        panel: "rgb(var(--panel) / <alpha-value>)",
        panel2: "rgb(var(--panel2) / <alpha-value>)",
        panel3: "rgb(var(--panel3) / <alpha-value>)",
        edge: "rgb(var(--edge) / <alpha-value>)",
        edge2: "rgb(var(--edge2) / <alpha-value>)",
        text: "rgb(var(--text) / <alpha-value>)",
        muted: "rgb(var(--muted) / <alpha-value>)",
        faint: "rgb(var(--faint) / <alpha-value>)",
        brand: "rgb(var(--brand) / <alpha-value>)",
        brandDim: "rgb(var(--brandDim) / <alpha-value>)",
        crit: "rgb(var(--crit) / <alpha-value>)",
        high: "rgb(var(--high) / <alpha-value>)",
        med: "rgb(var(--med) / <alpha-value>)",
        low: "rgb(var(--low) / <alpha-value>)",
        info: "rgb(var(--info) / <alpha-value>)",
        ok: "rgb(var(--ok) / <alpha-value>)",
        breach: "rgb(var(--crit) / <alpha-value>)",
        warn: "rgb(var(--high) / <alpha-value>)",
        danger: "rgb(var(--crit) / <alpha-value>)",
        accent: "rgb(var(--brand) / <alpha-value>)",
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "monospace"],
      },
      fontSize: {
        "2xs": ["10px", "14px"],
        xs: ["11px", "15px"],
        sm: ["12px", "16px"],
        base: ["13px", "18px"],
      },
      borderRadius: { DEFAULT: "3px", sm: "2px", md: "5px" },
      boxShadow: {
        card: "0 1px 0 rgba(255,255,255,0.025) inset, 0 1px 2px rgba(0,0,0,0.5)",
        raised: "0 8px 24px -8px rgba(0,0,0,0.7)",
        glow: "0 0 0 1px rgba(45,212,191,0.5), 0 0 12px -2px rgba(45,212,191,0.35)",
      },
    },
  },
  plugins: [],
};
