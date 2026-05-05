import React, { useState, useEffect } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";

import { isAuthenticated, onAuthChange } from "./api";

import Sidebar from "./components/Sidebar.jsx";
import Header from "./components/Header.jsx";
import LiveTerminal from "./components/LiveTerminal.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Engagement from "./pages/Engagement.jsx";
import Findings from "./pages/Findings.jsx";
import FindingDetail from "./pages/FindingDetail.jsx";
import KillChain from "./pages/KillChain.jsx";
import Scans from "./pages/Scans.jsx";

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
          </Routes>
        </div>
        <LiveTerminal />
      </div>
    </div>
  );
}
