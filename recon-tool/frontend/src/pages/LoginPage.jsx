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
    <div className="flex min-h-screen items-center justify-center bg-bg-app px-4">
      {/* Login card */}
      <div className="w-full max-w-[420px] animate-fade-in">
        <div className="rounded-lg border border-border-default bg-bg-card p-8 shadow-elevation-2">
          {/* Header */}
          <div className="mb-6 flex flex-col items-center text-center">
            <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-md border border-border-default bg-bg-elevated text-accent-primary">
              <ShieldMark className="h-7 w-7" />
            </div>
            <h1 className="text-xl font-semibold tracking-tight text-text-primary">ReconTool</h1>
            <p className="mt-1 text-sm text-text-secondary">Network Security Platform</p>
            <p className="mt-0.5 text-xs text-text-tertiary">Authorized lab environment only</p>
          </div>

          <div className="divider-premium my-6" />

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email field */}
            <div>
              <label htmlFor="email" className="mb-1.5 block text-sm font-medium text-text-primary">
                Email Address
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                className="w-full rounded-md border border-border-default bg-bg-input px-3 py-2.5 text-sm text-text-primary outline-none transition-colors duration-150 placeholder:text-text-tertiary focus:border-accent-primary"
                placeholder="analyst@recon.local"
                required
              />
            </div>

            {/* Password field */}
            <div>
              <label htmlFor="password" className="mb-1.5 block text-sm font-medium text-text-primary">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className="w-full rounded-md border border-border-default bg-bg-input px-3 py-2.5 pr-11 text-sm text-text-primary outline-none transition-colors duration-150 placeholder:text-text-tertiary focus:border-accent-primary"
                  placeholder="Password"
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

            {/* Submit button */}
            <button type="submit" className="btn-accent mt-2 w-full py-2.5">
              <span className="flex items-center justify-center gap-2">
                Sign In
                <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M5 12h14M12 5l7 7-7 7" />
                </svg>
              </span>
            </button>
          </form>

          {/* Footer info */}
          <div className="mt-6 border-t border-border-default pt-4 text-center">
            <p className="flex items-center justify-center gap-2 text-xs text-text-tertiary">
              <span className="h-1.5 w-1.5 rounded-full bg-status-success" />
              Secure connection · Lab environment only
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

