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
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      fontSize: {
        xs: ["10px", { lineHeight: "14px" }],
        sm: ["11px", { lineHeight: "16px" }],
        base: ["13px", { lineHeight: "18px" }],
        md: ["14px", { lineHeight: "20px" }],
        lg: ["16px", { lineHeight: "22px" }],
        xl: ["20px", { lineHeight: "28px" }],
        "2xl": ["26px", { lineHeight: "34px" }],
        display: ["32px", { lineHeight: "40px" }],
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
        card: "0 8px 24px -12px rgba(2, 12, 35, 0.72), 0 1px 0 rgba(0, 212, 255, 0.10)",
        "card-hover": "0 14px 36px -14px rgba(2, 12, 35, 0.82), 0 0 0 1px rgba(0, 212, 255, 0.18)",
        accent: "0 0 0 1px rgba(0, 212, 255, 0.28), 0 0 24px rgba(0, 212, 255, 0.24)",
        danger: "0 0 0 1px rgba(239, 68, 68, 0.32), 0 0 24px rgba(239, 68, 68, 0.28)",
        success: "0 0 0 1px rgba(34, 197, 94, 0.30), 0 0 24px rgba(34, 197, 94, 0.24)",
        /* Premium elevation shadows */
        "elevation-1": "0 4px 16px rgba(0, 0, 0, 0.3)",
        "elevation-2": "0 8px 24px rgba(0, 0, 0, 0.35)",
        "elevation-3": "0 12px 32px rgba(0, 0, 0, 0.4)",
        "elevation-4": "0 16px 48px rgba(0, 0, 0, 0.45)",
        /* Glass card glow */
        "card-glow": "0 0 0 1px rgba(0, 212, 255, 0.2), 0 0 32px rgba(0, 212, 255, 0.15)",
        "card-glow-hover": "0 0 0 1px rgba(0, 212, 255, 0.4), 0 0 40px rgba(0, 212, 255, 0.25)",
        /* Threat glows */
        "critical-glow": "0 0 0 1px rgba(239, 68, 68, 0.3), 0 0 24px rgba(239, 68, 68, 0.2)",
        "high-glow": "0 0 0 1px rgba(245, 158, 11, 0.25), 0 0 24px rgba(245, 158, 11, 0.18)",
      },
      keyframes: {
        "pulse-critical": {
          "0%, 100%": { boxShadow: "0 0 0 0 rgba(239, 68, 68, 0)" },
          "50%": { boxShadow: "0 0 0 2px rgba(239, 68, 68, 0.6), 0 0 24px rgba(239, 68, 68, 0.45)" },
        },
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
        "glow-pulse": {
          "0%, 100%": { textShadow: "0 0 10px rgba(0, 212, 255, 0.3), 0 0 20px rgba(0, 212, 255, 0.2)" },
          "50%": { textShadow: "0 0 20px rgba(0, 212, 255, 0.5), 0 0 40px rgba(0, 212, 255, 0.3)" },
        },
        "shimmer": {
          "0%": { backgroundPosition: "-1000px 0" },
          "100%": { backgroundPosition: "1000px 0" },
        },
        "float": {
          "0%, 100%": { transform: "translateY(0px)" },
          "50%": { transform: "translateY(-4px)" },
        },
        "scale-in": {
          "0%": { transform: "scale(0.95)", opacity: "0" },
          "100%": { transform: "scale(1)", opacity: "1" },
        },
        "rotate-in": {
          "0%": { transform: "rotate(-2deg) scale(0.95)", opacity: "0" },
          "100%": { transform: "rotate(0) scale(1)", opacity: "1" },
        },
      },
      animation: {
        "pulse-critical": "pulse-critical 2s ease-in-out infinite",
        "slide-in-top": "slide-in-top 300ms ease-out both",
        "slide-in-bottom": "slide-in-bottom 300ms ease-out both",
        "slide-in-left": "slide-in-left 300ms ease-out both",
        "slide-in-right": "slide-in-right 300ms ease-out both",
        "fade-in": "fade-in 200ms ease-out both",
        "count-up": "count-up 450ms ease-out both",
        "bar-rise": "bar-rise 400ms ease-out both",
        "glow-pulse": "glow-pulse 3s ease-in-out infinite",
        "float": "float 3s ease-in-out infinite",
        "scale-in": "scale-in 300ms cubic-bezier(0.34, 1.56, 0.64, 1) both",
        "rotate-in": "rotate-in 300ms cubic-bezier(0.34, 1.56, 0.64, 1) both",
      },
    },
  },
  plugins: [],
};
