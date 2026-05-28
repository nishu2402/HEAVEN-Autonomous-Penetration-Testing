// HEAVEN — Toast notification system
//
// Why: cross-page status updates (scan started, ticket created, regression
// detected) need a way to surface that's not buried in console.log or
// console.warn. Inline error-text in each page works for local errors but
// not for events that happen elsewhere (e.g. WebSocket scan-progress).
//
// Usage:
//   <ToastProvider>...</ToastProvider>             // wrap your app once
//   const toast = useToast();
//   toast.success("Scan launched", "ID a1b2c3d4");
//   toast.error("Replay failed", err.message);
//   toast.warning("Regression detected", "3 fixed findings came back");
//   toast.info("Loading benchmark report…");

import React, {
  createContext, useCallback, useContext, useEffect, useRef, useState,
} from "react";

const ToastContext = createContext(null);

let _autoId = 1;

const DEFAULT_DURATION_MS = 5000;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const timeoutsRef = useRef(new Map());

  const dismiss = useCallback((id) => {
    setToasts(ts => ts.filter(t => t.id !== id));
    const handle = timeoutsRef.current.get(id);
    if (handle) {
      clearTimeout(handle);
      timeoutsRef.current.delete(id);
    }
  }, []);

  const push = useCallback((kind, title, body = "", duration = DEFAULT_DURATION_MS) => {
    const id = _autoId++;
    setToasts(ts => [...ts, { id, kind, title, body }]);
    if (duration > 0) {
      const handle = setTimeout(() => dismiss(id), duration);
      timeoutsRef.current.set(id, handle);
    }
    return id;
  }, [dismiss]);

  const api = React.useMemo(() => ({
    success: (title, body, duration) => push("success", title, body, duration),
    warning: (title, body, duration) => push("warning", title, body, duration),
    error:   (title, body, duration) => push("error",   title, body, duration ?? 8000),
    info:    (title, body, duration) => push("info",    title, body, duration),
    dismiss,
  }), [push, dismiss]);

  useEffect(() => {
    // Cleanup outstanding timers on unmount
    const timers = timeoutsRef.current;
    return () => { for (const h of timers.values()) clearTimeout(h); };
  }, []);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toast-container" role="status" aria-live="polite">
        {toasts.map(t => (
          <div key={t.id} className={`toast toast-${t.kind}`}>
            <button
              type="button"
              className="toast-close"
              aria-label="Dismiss"
              onClick={() => dismiss(t.id)}
            >×</button>
            <div className="toast-title">{t.title}</div>
            {t.body && <div className="toast-body">{t.body}</div>}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    // Soft-fail when used outside a provider — pages still render, just
    // without toast capability. Useful during development.
    return {
      success: noop, warning: noop, error: noop, info: noop, dismiss: noop,
    };
  }
  return ctx;
}

function noop() {}
