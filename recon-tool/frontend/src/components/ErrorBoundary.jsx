import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    // Keep details in console for debugging while showing a safe fallback UI.
    // eslint-disable-next-line no-console
    console.error("UI runtime error:", error, errorInfo);
  }

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    return (
      <div
        style={{
          minHeight: "100vh",
          display: "grid",
          placeItems: "center",
          background: "#0f1117",
          color: "#e2e8f0",
          fontFamily: "Inter, -apple-system, BlinkMacSystemFont, sans-serif",
          padding: 24,
        }}
      >
        <div
          style={{
            width: "min(560px, 92vw)",
            border: "1px solid #2a3348",
            borderRadius: 12,
            background: "#161b24",
            padding: 20,
          }}
        >
          <h1 style={{ margin: 0, fontSize: 18, color: "#f8fafc" }}>UI crashed unexpectedly</h1>
          <p style={{ marginTop: 10, marginBottom: 14, color: "#94a3b8", fontSize: 14 }}>
            The interface encountered a runtime error. Refresh to recover.
          </p>
          <button
            onClick={() => window.location.reload()}
            style={{
              border: "1px solid #0891b2",
              background: "#0e7490",
              color: "#ecfeff",
              borderRadius: 8,
              padding: "8px 12px",
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            Reload UI
          </button>
          {this.state.error?.message && (
            <pre
              style={{
                marginTop: 12,
                whiteSpace: "pre-wrap",
                overflowWrap: "anywhere",
                color: "#fca5a5",
                fontSize: 12,
                background: "#111827",
                border: "1px solid #374151",
                borderRadius: 8,
                padding: 10,
              }}
            >
              {this.state.error.message}
            </pre>
          )}
        </div>
      </div>
    );
  }
}
