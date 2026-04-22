/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        "bg-app": "#0A0F17",
        "bg-sidebar": "#0E1522",
        "bg-card": "#121B2A",
        "bg-card-hover": "#162235",
        "bg-elevated": "#1A2740",
        "bg-input": "#0F1726",

        "threat-critical": {
          DEFAULT: "#EF4444",
          bg: "#3A1114",
          border: "#7F1D1D",
          text: "#FECACA",
          glow: "#F87171",
        },
        "threat-high": {
          DEFAULT: "#F59E0B",
          bg: "#3B2A0A",
          border: "#7A5A12",
          text: "#FDE68A",
          glow: "#FBBF24",
        },
        "threat-medium": {
          DEFAULT: "#F97316",
          bg: "#3C1E0E",
          border: "#7C3B13",
          text: "#FDBA74",
          glow: "#FB923C",
        },
        "threat-low": {
          DEFAULT: "#3B82F6",
          bg: "#0E223F",
          border: "#1D4ED8",
          text: "#BFDBFE",
          glow: "#60A5FA",
        },

        "accent-primary": "#00D4FF",
        "accent-hover": "#33DEFF",
        "accent-muted": "#00D4FF1A",
        "accent-border": "#00D4FF4D",

        "text-primary": "#E6EDF7",
        "text-secondary": "#A9B6CC",
        "text-tertiary": "#73819A",
        "text-disabled": "#4C586E",

        "status-success": "#22C55E",
        "status-warning": "#EAB308",
        "status-danger": "#EF4444",
        "status-info": "#38BDF8",
        "status-online": "#10B981",
        "status-offline": "#64748B",

        "os-linux": "#22C55E",
        "os-windows": "#3B82F6",
        "os-macos": "#A855F7",
        "os-unknown": "#6B7280",

        "border-default": "#FFFFFF0F",
        "border-elevated": "#FFFFFF1F",
        "border-accent": "#00D4FF4D",
        "border-danger": "#EF444466",
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
      },
      animation: {
        "pulse-critical": "pulse-critical 2s ease-in-out infinite",
        "slide-in-top": "slide-in-top 300ms ease-out both",
        "fade-in": "fade-in 200ms ease-out both",
        "count-up": "count-up 450ms ease-out both",
        "bar-rise": "bar-rise 400ms ease-out both",
      },
    },
  },
  plugins: [],
};
