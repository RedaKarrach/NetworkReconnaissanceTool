/** @type {import('tailwindcss').Config} */
const token = (name) => `rgb(var(${name}) / <alpha-value>)`;

module.exports = {
  content: ["./src/**/*.{js,jsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        "bg-app": token("--color-bg-app-rgb"),
        "bg-sidebar": token("--color-bg-sidebar-rgb"),
        "bg-card": token("--color-bg-card-rgb"),
        "bg-card-hover": token("--color-bg-card-hover-rgb"),
        "bg-elevated": token("--color-bg-elevated-rgb"),
        "bg-input": token("--color-bg-input-rgb"),

        "threat-critical": {
          DEFAULT: token("--color-threat-critical-rgb"),
          bg: token("--color-threat-critical-bg-rgb"),
          border: token("--color-threat-critical-border-rgb"),
          text: token("--color-threat-critical-text-rgb"),
          glow: token("--color-threat-critical-glow-rgb"),
        },
        "threat-high": {
          DEFAULT: token("--color-threat-high-rgb"),
          bg: token("--color-threat-high-bg-rgb"),
          border: token("--color-threat-high-border-rgb"),
          text: token("--color-threat-high-text-rgb"),
          glow: token("--color-threat-high-glow-rgb"),
        },
        "threat-medium": {
          DEFAULT: token("--color-threat-medium-rgb"),
          bg: token("--color-threat-medium-bg-rgb"),
          border: token("--color-threat-medium-border-rgb"),
          text: token("--color-threat-medium-text-rgb"),
          glow: token("--color-threat-medium-glow-rgb"),
        },
        "threat-low": {
          DEFAULT: token("--color-threat-low-rgb"),
          bg: token("--color-threat-low-bg-rgb"),
          border: token("--color-threat-low-border-rgb"),
          text: token("--color-threat-low-text-rgb"),
          glow: token("--color-threat-low-glow-rgb"),
        },

        "accent-primary": token("--color-accent-primary-rgb"),
        "accent-hover": token("--color-accent-hover-rgb"),
        "accent-muted": "rgb(var(--color-accent-muted-rgb) / 0.14)",
        "accent-border": token("--color-accent-border-rgb"),

        "text-primary": token("--color-text-primary-rgb"),
        "text-secondary": token("--color-text-secondary-rgb"),
        "text-tertiary": token("--color-text-tertiary-rgb"),
        "text-disabled": token("--color-text-disabled-rgb"),

        "status-success": token("--color-status-success-rgb"),
        "status-warning": token("--color-status-warning-rgb"),
        "status-danger": token("--color-status-danger-rgb"),
        "status-info": token("--color-status-info-rgb"),
        "status-online": token("--color-status-online-rgb"),
        "status-offline": token("--color-status-offline-rgb"),

        "os-linux": token("--color-os-linux-rgb"),
        "os-windows": token("--color-os-windows-rgb"),
        "os-macos": token("--color-os-macos-rgb"),
        "os-unknown": token("--color-os-unknown-rgb"),

        "border-default": token("--color-border-default-rgb"),
        "border-elevated": token("--color-border-elevated-rgb"),
        "border-accent": token("--color-border-accent-rgb"),
        "border-danger": token("--color-border-danger-rgb"),
        "border-premium": token("--color-border-premium-rgb"),
      },
      fontFamily: {
        sans: [
          "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Noto Sans",
          "Helvetica", "Arial", "sans-serif",
        ],
        mono: [
          "ui-monospace", "SFMono-Regular", "SF Mono", "Menlo", "Consolas",
          "Liberation Mono", "Courier New", "monospace",
        ],
      },
      fontSize: {
        xs: ["11px", { lineHeight: "16px" }],
        sm: ["12px", { lineHeight: "16px" }],
        base: ["14px", { lineHeight: "20px" }],
        md: ["15px", { lineHeight: "22px" }],
        lg: ["16px", { lineHeight: "24px" }],
        xl: ["20px", { lineHeight: "28px" }],
        "2xl": ["24px", { lineHeight: "32px" }],
        display: ["30px", { lineHeight: "38px" }],
      },
      spacing: {
        // 4px base scale is Tailwind's default; nothing to override.
      },
      borderRadius: {
        sm: "6px",
        md: "8px",
        lg: "12px",
        xl: "16px",
        "2xl": "20px",
        full: "9999px",
      },
      boxShadow: {
        /* Flat, restrained elevation only — no colored glows. */
        card: "0 1px 2px rgba(0, 0, 0, 0.18)",
        "card-hover": "0 2px 6px rgba(0, 0, 0, 0.22)",
        accent: "0 0 0 1px rgba(129, 140, 214, 0.40)",
        danger: "0 0 0 1px rgba(220, 38, 38, 0.40)",
        success: "0 0 0 1px rgba(34, 197, 94, 0.35)",
        "elevation-1": "0 1px 2px rgba(0, 0, 0, 0.18)",
        "elevation-2": "0 2px 6px rgba(0, 0, 0, 0.20)",
        "elevation-3": "0 4px 12px rgba(0, 0, 0, 0.24)",
        "elevation-4": "0 8px 20px rgba(0, 0, 0, 0.28)",
        "card-glow": "0 1px 2px rgba(0, 0, 0, 0.18)",
        "card-glow-hover": "0 2px 6px rgba(0, 0, 0, 0.22)",
        "critical-glow": "0 0 0 1px rgba(220, 38, 38, 0.35)",
        "high-glow": "0 0 0 1px rgba(245, 158, 11, 0.30)",
      },
      keyframes: {
        "slide-in-top": {
          "0%": { transform: "translateY(-12px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        "slide-in-bottom": {
          "0%": { transform: "translateY(12px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        "slide-in-left": {
          "0%": { transform: "translateX(-12px)", opacity: "0" },
          "100%": { transform: "translateX(0)", opacity: "1" },
        },
        "slide-in-right": {
          "0%": { transform: "translateX(12px)", opacity: "0" },
          "100%": { transform: "translateX(0)", opacity: "1" },
        },
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        "count-up": {
          "0%": { transform: "translateY(4px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        "bar-rise": {
          "0%": { height: "0" },
          "100%": { height: "100%" },
        },
        "scale-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        "alert-flash": {
          "0%": { backgroundColor: "rgba(129, 140, 214, 0.14)" },
          "100%": { backgroundColor: "transparent" },
        },
      },
      animation: {
        /* Functional, non-looping only. Legacy looping names map to none. */
        "slide-in-top": "slide-in-top 150ms ease-out both",
        "slide-in-bottom": "slide-in-bottom 150ms ease-out both",
        "slide-in-left": "slide-in-left 150ms ease-out both",
        "slide-in-right": "slide-in-right 150ms ease-out both",
        "fade-in": "fade-in 150ms ease-out both",
        "count-up": "count-up 150ms ease-out both",
        "bar-rise": "bar-rise 300ms ease-out both",
        "alert-flash": "alert-flash 600ms ease-out 1",
        "pulse-critical": "none",
        "glow-pulse": "none",
        "float": "none",
        "scale-in": "scale-in 150ms ease-out both",
        "rotate-in": "fade-in 150ms ease-out both",
        "shimmer": "none",
      },
    },
  },
  plugins: [],
};
