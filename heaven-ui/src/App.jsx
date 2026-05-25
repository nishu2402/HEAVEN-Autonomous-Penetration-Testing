import React, { useState, useEffect } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";

import { isAuthenticated, onAuthChange } from "./api";

import Sidebar      from "./components/Sidebar.jsx";
import Header       from "./components/Header.jsx";
import LoginPage    from "./pages/LoginPage.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Engagement from "./pages/Engagement.jsx";
import Findings from "./pages/Findings.jsx";
import FindingDetail from "./pages/FindingDetail.jsx";
import KillChain from "./pages/KillChain.jsx";
import Scans from "./pages/Scans.jsx";
import AIPlans from "./pages/AIPlans.jsx";
import Benchmark from "./pages/Benchmark.jsx";
import Methodology from "./pages/Methodology.jsx";
import AutonomousPage from "./pages/Autonomous.jsx";
import CoveragePage from "./pages/Coverage.jsx";
import PostexPage from "./pages/Postex.jsx";
import KnowledgePage from "./pages/Knowledge.jsx";
import LateralPage from "./pages/Lateral.jsx";
import DiffPage from "./pages/Diff.jsx";
import TicketsPage from "./pages/Tickets.jsx";
import SastPage from "./pages/Sast.jsx";
import WatchPage from "./pages/Watch.jsx";

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
  );
}

function Shell() {
  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main-pane">
        <Header />
        <div className="content">
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
        </div>
      </div>
    </div>
  );
}
