import React, { useState } from "react";

function ShieldMark({ className = "h-12 w-12" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <path d="M12 3 4.5 6v6.2c0 5.2 3.2 8.7 7.5 10.8 4.3-2.1 7.5-5.6 7.5-10.8V6L12 3Z" />
      <path d="M12 8v8" />
      <path d="M8.8 11.2h6.4" />
    </svg>
  );
}

function EyeIcon({ className = "h-4 w-4" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z" />
      <circle cx="12" cy="12" r="2.5" />
    </svg>
  );
}

function EyeOffIcon({ className = "h-4 w-4" }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={className}>
      <path d="M3 3 21 21" />
      <path d="M10.7 6.2A11.7 11.7 0 0 1 12 6c6.5 0 10 6 10 6a16 16 0 0 1-3.3 3.9" />
      <path d="M6.2 8.5C3.6 10.3 2 12 2 12s3.5 6 10 6c1.2 0 2.3-.2 3.3-.6" />
      <path d="M9.9 9.9A3 3 0 0 0 12 15a3 3 0 0 0 2.1-.9" />
    </svg>
  );
}

export default function LoginPage({ onLogin }) {
  const [email, setEmail] = useState("analyst@recon.local");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  function handleSubmit(event) {
    event.preventDefault();
    onLogin({ email });
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-bg-app px-4">
      {/* Atmospheric background effects */}
      <div className="pointer-events-none absolute inset-0">
        <div className="holo-ring holo-ring-primary" />
        <div className="holo-ring holo-ring-secondary" />
        {/* Grid pattern */}
        <div
          className="absolute inset-0"
          style={{
            backgroundImage:
              "repeating-linear-gradient(0deg, rgba(0,212,255,0.02) 0px, rgba(0,212,255,0.02) 1px, transparent 1px, transparent 32px), repeating-linear-gradient(90deg, rgba(0,212,255,0.02) 0px, rgba(0,212,255,0.02) 1px, transparent 1px, transparent 32px)",
            animation: "fade-in 400ms ease-out both",
          }}
        />

        {/* Top-right glow */}
        <div className="absolute -right-32 -top-32 h-[500px] w-[500px] rounded-full bg-accent-primary blur-3xl"
          style={{ opacity: 0.04 }}
        />

        {/* Bottom-left glow */}
        <div className="absolute -bottom-40 -left-40 h-[500px] w-[500px] rounded-full bg-threat-critical blur-3xl"
          style={{ opacity: 0.02 }}
        />

        {/* Center soft glow */}
        <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 h-[600px] w-[600px] rounded-full bg-accent-primary blur-3xl"
          style={{ opacity: 0.02 }}
        />
      </div>

      {/* Login Card */}
      <div className="relative w-full max-w-[480px] animate-scale-in scene-3d">
        {/* Card glow background */}
        <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-accent-primary to-threat-low blur-2xl opacity-0 group-hover/card:opacity-20 transition-opacity duration-500"
          style={{ animation: "fade-in 600ms ease-out 200ms both" }}
        />

        {/* Main card */}
        <div
          className="relative rounded-2xl border border-border-premium p-8 sm:p-10 transition-all duration-500 group/card tilt-3d"
          style={{
            background: "linear-gradient(135deg, rgba(18, 27, 42, 0.75) 0%, rgba(22, 34, 53, 0.65) 100%)",
            backdropFilter: "blur(24px)",
            WebkitBackdropFilter: "blur(24px)",
            boxShadow: "0 14px 46px rgba(0, 0, 0, 0.36), 0 0 0 1px rgba(0, 212, 255, 0.18)",
          }}
        >
          {/* Header */}
          <div className="flex flex-col items-center text-center mb-8 animate-slide-in-top">
            {/* Shield icon with glow */}
            <div className="mb-6 relative">
              <div className="absolute inset-0 rounded-full bg-accent-primary blur-xl opacity-0 group-hover/card:opacity-20 transition-opacity duration-300"
                style={{ animation: "fade-in 400ms ease-out 300ms both" }}
              />
              <div className="relative text-accent-primary animate-float"
                style={{ animationDelay: "0ms" }}
              >
                <ShieldMark className="h-14 w-14" />
              </div>
            </div>

            {/* Brand name */}
            <h1 className="text-3xl font-bold text-text-primary tracking-tight">
              <span className="text-gradient">ReconTool</span>
            </h1>

            {/* Tagline */}
            <p className="mt-2 text-sm font-medium text-text-secondary">
              Advanced Network Security Platform
            </p>
            <p className="mt-1 text-xs text-text-tertiary">
              Enterprise-grade reconnaissance & monitoring
            </p>
          </div>

          {/* Divider */}
          <div className="my-8 h-px bg-gradient-to-r from-transparent via-border-elevated to-transparent" />

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Email field */}
            <div className="group/field animate-slide-in-bottom" style={{ animationDelay: "60ms" }}>
              <label htmlFor="email" className="mb-2 block text-sm font-semibold text-text-primary">
                Email Address
              </label>
              <div className="relative">
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  className="w-full rounded-lg border border-border-default bg-bg-input/60 px-4 py-3 text-sm text-text-primary outline-none transition-all duration-200 placeholder:text-text-tertiary focus:border-accent-primary focus:ring-2 focus:ring-accent-muted focus:bg-bg-input group-hover/field:border-border-elevated"
                  style={{ backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}
                  placeholder="analyst@recon.local"
                  required
                />
              </div>
            </div>

            {/* Password field */}
            <div className="group/field animate-slide-in-bottom" style={{ animationDelay: "120ms" }}>
              <label htmlFor="password" className="mb-2 block text-sm font-semibold text-text-primary">
                Password
              </label>
              <div className="relative group/pwd">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className="w-full rounded-lg border border-border-default bg-bg-input/60 px-4 py-3 pr-11 text-sm text-text-primary outline-none transition-all duration-200 placeholder:text-text-tertiary focus:border-accent-primary focus:ring-2 focus:ring-accent-muted focus:bg-bg-input group-hover/field:border-border-elevated"
                  style={{ backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}
                  placeholder="••••••••"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary transition-all duration-150 hover:text-text-secondary hover:scale-110 active:scale-95"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOffIcon /> : <EyeIcon />}
                </button>
              </div>
            </div>

            {/* Submit button */}
            <button
              type="submit"
              className="group relative mt-8 w-full overflow-hidden rounded-lg px-6 py-3.5 text-base font-semibold text-bg-app transition-all duration-300 active:scale-95 animate-slide-in-bottom"
              style={{ animationDelay: "180ms" }}
            >
              {/* Button gradient background */}
              <div className="absolute inset-0 bg-gradient-to-r from-accent-primary via-accent-hover to-accent-primary"
                style={{
                  backgroundSize: "200% 100%",
                  animation: "shimmer 2s ease-in-out infinite",
                }}
              />

              {/* Glow effect */}
              <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                style={{
                  boxShadow: "0 0 20px rgba(0, 212, 255, 0.5), inset 0 0 20px rgba(255, 255, 255, 0.1)",
                }}
              />

              <span className="relative flex items-center justify-center gap-2">
                Sign In to ReconTool
                <svg className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-1" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M5 12h14M12 5l7 7-7 7" />
                </svg>
              </span>
            </button>
          </form>

          {/* Footer info */}
          <div className="mt-8 pt-6 border-t border-border-default/50 text-center animate-fade-in" style={{ animationDelay: "240ms" }}>
            <p className="text-xs text-text-tertiary flex items-center justify-center gap-2">
              <span className="relative flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-status-success opacity-75" />
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-status-success" />
              </span>
              Secure connection · Lab environment only
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

