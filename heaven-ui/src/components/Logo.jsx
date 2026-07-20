// HEAVEN — the "Ascendant Aegis" brand mark. Single source of truth for the
// logo across the whole web app (Sidebar, LoginPage, forced-password screen).
//
// Design: a faceted violet→cyan→emerald hexagonal aegis (the guardian; its six
// pointed vertices read as a targeting reticle — offensive-security precision)
// enclosing an "H" whose crossbar rises to a glowing apex node — ascension, the
// literal meaning of HEAVEN. Kept in lock-step with heaven-ui/public/heaven-mark.svg,
// the favicon in index.html, and the report/CLI marks.
import React, { useId } from "react";

export default function Logo({ size = 40, className = "", title = "HEAVEN", glow = true }) {
  // Unique gradient/filter ids per instance so multiple logos on one page
  // (e.g. sidebar + a modal) never collide and blank each other out.
  const uid = useId().replace(/[^a-zA-Z0-9]/g, "");
  const edge = `hvnEdge-${uid}`;
  const mono = `hvnMono-${uid}`;
  const core = `hvnCore-${uid}`;
  const blur = `hvnGlow-${uid}`;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 128 128"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label={title}
      className={className}
    >
      <title>{title}</title>
      <defs>
        <linearGradient id={edge} x1="18" y1="12" x2="110" y2="118" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#6D7CFF" />
          <stop offset="0.5" stopColor="#22D3EE" />
          <stop offset="1" stopColor="#34E5A3" />
        </linearGradient>
        <linearGradient id={mono} x1="48" y1="45" x2="80" y2="88" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#9BA8FF" />
          <stop offset="0.5" stopColor="#34E5A3" />
          <stop offset="1" stopColor="#22D3EE" />
        </linearGradient>
        <radialGradient id={core} cx="0.5" cy="0.42" r="0.72">
          <stop offset="0" stopColor="#101B2E" />
          <stop offset="1" stopColor="#070A12" />
        </radialGradient>
        {glow && (
          <filter id={blur} x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="2.1" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        )}
      </defs>

      {/* aegis: faceted hexagonal gem (guardian + reticle vertices) */}
      <polygon
        points="64,10 110,37 110,91 64,118 18,91 18,37"
        fill={`url(#${core})`}
        stroke={`url(#${edge})`}
        strokeWidth="4.5"
        strokeLinejoin="round"
      />
      <polygon
        points="64,22 101,44 101,84 64,106 27,84 27,44"
        stroke={`url(#${edge})`}
        strokeWidth="1.1"
        strokeOpacity="0.32"
        strokeLinejoin="round"
      />

      {/* monogram H whose crossbar ascends to a glowing apex */}
      <g
        stroke={`url(#${mono})`}
        strokeWidth="7.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        filter={glow ? `url(#${blur})` : undefined}
      >
        <path d="M48 50V88" />
        <path d="M80 50V88" />
        <path d="M48 72 64 54 80 72" />
      </g>
      <circle cx="64" cy="45" r="4.6" fill="#EAFBF4" filter={glow ? `url(#${blur})` : undefined} />
    </svg>
  );
}
