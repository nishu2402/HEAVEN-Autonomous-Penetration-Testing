// HEAVEN — Error boundary
//
// Without this, any render error in any page white-screens the whole SPA with
// no recovery (which is exactly what a dropped import once did). This catches
// the error, keeps the app shell alive, and offers Reload / Back-to-dashboard.
//
// In App.jsx it's keyed by the route path, so simply navigating to another
// page remounts it and clears the error — no full reload required.

import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Surface in the console for debugging; never swallow silently.
    console.error("HEAVEN UI render error:", error, info?.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;

    const message = String(this.state.error?.message || this.state.error);
    return (
      <div className="error-boundary" role="alert">
        <div className="error-boundary-card">
          <div className="error-boundary-icon">⚠</div>
          <h1 className="error-boundary-title">Something went wrong</h1>
          <p className="error-boundary-text">
            This page hit an unexpected error. Your session is still active —
            try reloading, or head back to the dashboard.
          </p>
          <pre className="error-boundary-detail">{message}</pre>
          <div className="error-boundary-actions">
            <button className="btn" type="button" onClick={() => window.location.reload()}>
              ↻ Reload page
            </button>
            <a className="btn-ghost" href="/">Back to dashboard</a>
          </div>
        </div>
      </div>
    );
  }
}
