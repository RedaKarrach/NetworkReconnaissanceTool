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
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage:
            "repeating-linear-gradient(0deg, rgba(255,255,255,0.03) 0px, rgba(255,255,255,0.03) 1px, transparent 1px, transparent 32px), repeating-linear-gradient(90deg, rgba(255,255,255,0.03) 0px, rgba(255,255,255,0.03) 1px, transparent 1px, transparent 32px)",
          animation: "fade-in 200ms ease-out both",
        }}
      />

      <div
        className="pointer-events-none absolute -right-28 -top-28 h-[420px] w-[420px] rounded-full bg-accent-primary blur-3xl"
        style={{ opacity: 0.03 }}
      />

      <div
        className="relative w-full max-w-[420px] rounded-2xl border border-border-elevated bg-bg-card/80 p-10 shadow-card"
        style={{ backdropFilter: "blur(24px)" }}
      >
        <div className="flex flex-col items-center text-center">
          <div className="mb-4 text-accent-primary">
            <ShieldMark className="h-12 w-12" />
          </div>
          <h1 className="text-xl font-bold text-text-primary">ReconTool</h1>
          <p className="mt-1 text-sm text-text-tertiary">Security Operations Platform</p>
        </div>

        <div className="my-6 h-px w-full bg-border-default" />

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="email" className="mb-1.5 block text-sm font-medium text-text-secondary">
              Email address
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="w-full rounded-md border border-border-default bg-bg-input px-4 py-3 font-mono text-sm text-text-primary outline-none transition-colors duration-150 placeholder:text-text-tertiary focus:border-accent-border focus:ring-2 focus:ring-accent-primary"
              placeholder="you@lab.local"
              required
            />
          </div>

          <div>
            <label htmlFor="password" className="mb-1.5 block text-sm font-medium text-text-secondary">
              Password
            </label>
            <div className="relative">
              <input
                id="password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="w-full rounded-md border border-border-default bg-bg-input px-4 py-3 pr-11 font-mono text-sm text-text-primary outline-none transition-colors duration-150 placeholder:text-text-tertiary focus:border-accent-border focus:ring-2 focus:ring-accent-primary"
                placeholder="••••••••"
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword((prev) => !prev)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary transition-colors duration-150 hover:text-text-secondary"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOffIcon /> : <EyeIcon />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className="mt-6 w-full rounded-md bg-gradient-to-r from-accent-hover to-accent-primary py-3 text-base font-semibold text-text-primary transition duration-150 hover:-translate-y-px hover:brightness-110 active:scale-[0.98]"
          >
            Sign in
          </button>
        </form>

        <p className="mt-4 text-center text-xs text-text-tertiary">🔒 Secured connection · Lab environment only</p>
      </div>
    </div>
  );
}
