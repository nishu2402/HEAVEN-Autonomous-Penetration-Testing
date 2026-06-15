import React, { Suspense, lazy, useState, useEffect } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";

import { isAuthenticated, onAuthChange, needsPasswordChange, onSessionExpired } from "./api";

// Eager: the app shell + the login screen. These paint first, so they stay in
// the main bundle. Everything below is code-split (React.lazy) so the heavy
// stuff — especially the three.js 3D topology — never lands in first load.
import Sidebar from "./components/Sidebar.jsx";
import Header from "./components/Header.jsx";
import { ToastProvider, useToast } from "./components/Toast.jsx";
import { CommandPalette } from "./components/CommandPalette.jsx";
import Tour from "./components/Tour.jsx";
import ErrorBoundary from "./components/ErrorBoundary.jsx";
import ForcedPasswordChange from "./components/ForcedPasswordChange.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import NotFound from "./pages/NotFound.jsx";

// Lazy: one chunk per authenticated page, fetched on navigation.
const Dashboard      = lazy(() => import("./pages/Dashboard.jsx"));
const Engagement     = lazy(() => import("./pages/Engagement.jsx"));
const Findings       = lazy(() => import("./pages/Findings.jsx"));
const FindingDetail  = lazy(() => import("./pages/FindingDetail.jsx"));
const KillChain      = lazy(() => import("./pages/KillChain.jsx"));
const Scans          = lazy(() => import("./pages/Scans.jsx"));
const AIPlans        = lazy(() => import("./pages/AIPlans.jsx"));
const Benchmark      = lazy(() => import("./pages/Benchmark.jsx"));
const Methodology    = lazy(() => import("./pages/Methodology.jsx"));
const AutonomousPage = lazy(() => import("./pages/Autonomous.jsx"));
const CoveragePage   = lazy(() => import("./pages/Coverage.jsx"));
const PostexPage     = lazy(() => import("./pages/Postex.jsx"));
const KnowledgePage  = lazy(() => import("./pages/Knowledge.jsx"));
const LateralPage    = lazy(() => import("./pages/Lateral.jsx"));
const DiffPage       = lazy(() => import("./pages/Diff.jsx"));
const TicketsPage    = lazy(() => import("./pages/Tickets.jsx"));
const SastPage       = lazy(() => import("./pages/Sast.jsx"));
const WatchPage      = lazy(() => import("./pages/Watch.jsx"));
const Reports        = lazy(() => import("./pages/Reports.jsx"));
const SettingsPage   = lazy(() => import("./pages/Settings.jsx"));
const HealthPage     = lazy(() => import("./pages/Health.jsx"));

function RouteFallback() {
  return (
    <div className="route-fallback">
      <span className="route-spinner" />
      <span>Loading…</span>
    </div>
  );
}

function ProtectedRoute({ children }) {
  const [authed, setAuthed] = useState(isAuthenticated());
  const loc = useLocation();

  useEffect(() => {
    return onAuthChange(() => setAuthed(isAuthenticated()));
  }, []);

  if (!authed) {
    return <Navigate to="/login" state={{ from: loc }} replace />;
  }
  return children;
}

// Lives inside ToastProvider so it can raise a toast when api.js reports a 401.
function SessionExpiryWatcher() {
  const toast = useToast();
  useEffect(
    () => onSessionExpired((msg) => toast.warning("Session expired", msg)),
    [toast],
  );
  return null;
}

export default function App() {
  return (
    <ToastProvider>
      <SessionExpiryWatcher />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <Shell />
            </ProtectedRoute>
          }
        />
      </Routes>
    </ToastProvider>
  );
}

function Shell() {
  const [mustChange, setMustChange] = useState(needsPasswordChange());
  const [navOpen, setNavOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    return onAuthChange(() => setMustChange(needsPasswordChange()));
  }, []);

  // Close the mobile nav whenever the route changes.
  useEffect(() => { setNavOpen(false); }, [location.pathname]);

  return (
    <div className={"app-shell" + (navOpen ? " nav-open" : "")}>
      {mustChange && <ForcedPasswordChange onDone={() => setMustChange(false)} />}
      {!mustChange && <Tour />}
      <CommandPalette />
      <Sidebar />
      <div className="nav-backdrop" onClick={() => setNavOpen(false)} aria-hidden="true" />
      <div className="main-pane">
        <Header onMenu={() => setNavOpen((o) => !o)} />
        <div className="content">
          {/* Keyed by path so navigating to another route clears a crashed page. */}
          <ErrorBoundary key={location.pathname}>
            <Suspense fallback={<RouteFallback />}>
              <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/engagement" element={<Engagement />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/findings/:id" element={<FindingDetail />} />
              <Route path="/kill-chain" element={<KillChain />} />
              <Route path="/scans" element={<Scans />} />
              <Route path="/diff" element={<DiffPage />} />
              <Route path="/autonomous" element={<AutonomousPage />} />
              <Route path="/coverage" element={<CoveragePage />} />
              <Route path="/postex" element={<PostexPage />} />
              <Route path="/lateral" element={<LateralPage />} />
              <Route path="/knowledge" element={<KnowledgePage />} />
              <Route path="/ai-plans" element={<AIPlans />} />
              <Route path="/benchmark" element={<Benchmark />} />
              <Route path="/methodology" element={<Methodology />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/health" element={<HealthPage />} />
              <Route path="/tickets" element={<TicketsPage />} />
              <Route path="/sast" element={<SastPage />} />
              <Route path="/watch" element={<WatchPage />} />
              <Route path="*" element={<NotFound />} />
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </div>
      </div>
    </div>
  );
}
