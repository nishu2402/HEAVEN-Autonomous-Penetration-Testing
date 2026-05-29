import React, { Suspense, lazy, useState, useEffect } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";

import { isAuthenticated, onAuthChange } from "./api";

// Eager: the app shell + the login screen. These paint first, so they stay in
// the main bundle. Everything below is code-split (React.lazy) so the heavy
// stuff — especially the three.js 3D topology — never lands in first load.
import Sidebar from "./components/Sidebar.jsx";
import Header from "./components/Header.jsx";
import { ToastProvider } from "./components/Toast.jsx";
import { CommandPalette } from "./components/CommandPalette.jsx";
import LoginPage from "./pages/LoginPage.jsx";

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

export default function App() {
  return (
    <ToastProvider>
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
  return (
    <div className="app-shell">
      <CommandPalette />
      <Sidebar />
      <div className="main-pane">
        <Header />
        <div className="content">
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
              <Route path="/tickets" element={<TicketsPage />} />
              <Route path="/sast" element={<SastPage />} />
              <Route path="/watch" element={<WatchPage />} />
            </Routes>
          </Suspense>
        </div>
      </div>
    </div>
  );
}
