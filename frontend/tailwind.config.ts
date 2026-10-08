import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#0A0E14",
        panel: "#131A24",
        elevated: "#1C2530",
        border: {
          DEFAULT: "#2A3441",
          subtle: "#1E2733",
        },
        ink: {
          DEFAULT: "#E6EAF0",
          muted: "#8B96A5",
          faint: "#5B6675",
        },
        accent: {
          DEFAULT: "#5B8DEF",
          dim: "#3A5A9E",
        },
        severity: {
          critical: "#E5484D",
          "critical-bg": "#2E1417",
          high: "#F0883E",
          "high-bg": "#2E1D0F",
          medium: "#F2C94C",
          "medium-bg": "#2C270F",
          low: "#6FCF97",
          "low-bg": "#132A1D",
          info: "#8B96A5",
          "info-bg": "#1A2029",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      borderRadius: {
        sm: "3px",
        DEFAULT: "4px",
        md: "6px",
      },
    },
  },
  plugins: [],
};

export default config;
