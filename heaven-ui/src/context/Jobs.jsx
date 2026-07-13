// HEAVEN — global long-running-operation store.
//
// The problem this solves: pages like Post-Ex / Lateral / SAST fire a *blocking*
// request (`await Postex.full(...)`) and keep the spinner + result in the page
// component's own state. React Router unmounts that page the moment you navigate
// away, destroying `loading`/`result`; when you come back the page re-mounts
// fresh, so the operation *looks* like it stopped and its result is lost — even
// though the request is still running (fetch is not tied to a component) and the
// server finishes the work regardless.
//
// The fix: lift that state OUT of the page into a provider mounted once at the
// app root (above the router). A job started here keeps running and its result is
// captured no matter which page is mounted, so navigating away and back — or
// watching from the header — always reflects the true state. This is the single
// mechanism every long-running action in the app funnels through.

import React, { createContext, useCallback, useContext, useState } from "react";

const JobsCtx = createContext(null);

export function JobsProvider({ children }) {
  // key -> { key, label, kind, status: 'running'|'done'|'error',
  //          startedAt, endedAt, result, error }
  const [jobs, setJobs] = useState({});

  // Patch a job only if it still exists (a user may have cleared it mid-flight).
  const patch = useCallback((key, next) => {
    setJobs((j) => (j[key] ? { ...j, [key]: { ...j[key], ...next } } : j));
  }, []);

  // Start (or restart) the job identified by `key`. `run` is a function returning
  // a promise; it runs independently of any page, and settling updates the store.
  const startJob = useCallback((key, meta, run) => {
    setJobs((j) => ({
      ...j,
      [key]: {
        key,
        status: "running",
        startedAt: Date.now(),
        endedAt: null,
        result: null,
        error: null,
        ...meta,
      },
    }));
    Promise.resolve()
      .then(run)
      .then((result) => patch(key, { status: "done", result, endedAt: Date.now() }))
      .catch((err) =>
        patch(key, { status: "error", error: err?.message || String(err), endedAt: Date.now() }));
  }, [patch]);

  const clearJob = useCallback((key) => {
    setJobs((j) => {
      if (!j[key]) return j;
      const n = { ...j };
      delete n[key];
      return n;
    });
  }, []);

  return (
    <JobsCtx.Provider value={{ jobs, startJob, clearJob }}>
      {children}
    </JobsCtx.Provider>
  );
}

export function useJobs() {
  const ctx = useContext(JobsCtx);
  if (!ctx) throw new Error("useJobs must be used within <JobsProvider>");
  return ctx;
}

// Per-slot hook: one logical operation identified by a stable `key` (e.g.
// "postex", "lateral"). Returns the live job plus convenience flags so a page can
// drop it in where it previously kept local loading/result/error state.
export function useJob(key) {
  const { jobs, startJob, clearJob } = useJobs();
  const job = jobs[key] || null;
  const start = useCallback((meta, run) => startJob(key, meta, run), [startJob, key]);
  const clear = useCallback(() => clearJob(key), [clearJob, key]);
  return {
    job,
    loading: job?.status === "running",
    result: job?.status === "done" ? job.result : null,
    error: job?.status === "error" ? job.error : null,
    start,
    clear,
  };
}
