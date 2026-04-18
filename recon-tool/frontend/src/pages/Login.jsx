import React, { useState } from "react";

const ADMIN_USER = process.env.REACT_APP_ADMIN_USER || "root";
const ADMIN_PASS = process.env.REACT_APP_ADMIN_PASSWORD || "root";

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  function handleSubmit(e) {
    e.preventDefault();
    setError("");

    if (username !== ADMIN_USER || password !== ADMIN_PASS) {
      setError("Invalid credentials");
      return;
    }

    onLogin({ username });
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        background: "radial-gradient(circle at top, #101827 0%, #0b0f1a 45%, #05070c 100%)",
        color: "#e2e8f0",
        fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
        padding: 24,
      }}
    >
      <div
        style={{
          width: "min(480px, 92vw)",
          border: "1px solid #1f2937",
          borderRadius: 16,
          background: "linear-gradient(180deg, rgba(15,23,42,.9), rgba(9,14,24,.95))",
          boxShadow: "0 30px 80px rgba(0,0,0,.55)",
          padding: 28,
        }}
      >
        <div style={{ fontSize: 12, color: "#94a3b8", textTransform: "uppercase", letterSpacing: ".12em" }}>
          ReconTool Secure Access
        </div>
        <h1 style={{ margin: "10px 0 6px", fontSize: 22, color: "#f8fafc" }}>Root Console</h1>
        <p style={{ margin: 0, color: "#94a3b8", fontSize: 13 }}>
          Sign in to view endpoints, alerts, and inventory.
        </p>

        <form onSubmit={handleSubmit} style={{ marginTop: 18, display: "grid", gap: 12 }}>
          <div>
            <label style={{ display: "block", fontSize: 11, color: "#94a3b8", marginBottom: 6 }}>Username</label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="root"
              className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 w-full"
            />
          </div>
          <div>
            <label style={{ display: "block", fontSize: 11, color: "#94a3b8", marginBottom: 6 }}>Password</label>
            <input
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              type="password"
              placeholder="••••••••"
              className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 w-full"
            />
          </div>

          {error && (
            <div className="text-red-400 text-sm bg-red-900/40 border border-red-700 rounded px-3 py-2">
              {error}
            </div>
          )}

          <button
            type="submit"
            className="w-full py-2.5 rounded text-sm font-semibold bg-cyan-700 hover:bg-cyan-600 text-white"
          >
            Enter Dashboard
          </button>
        </form>
      </div>
    </div>
  );
}
