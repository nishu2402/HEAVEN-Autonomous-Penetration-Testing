// HEAVEN — 404 catch-all
//
// Before this, an unknown/old URL rendered a blank content area. Now it shows
// a clear "page not found" with a way back.

import React from "react";
import { EmptyState } from "../components/Skeleton.jsx";

export default function NotFound() {
  return (
    <div className="page">
      <EmptyState
        icon="🧭"
        headline="Page not found"
        body="The page you're looking for doesn't exist or may have moved."
        cta="Back to dashboard"
        ctaTo="/"
      />
    </div>
  );
}
