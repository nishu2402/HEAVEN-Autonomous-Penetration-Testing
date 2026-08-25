import React, { useEffect, useRef, useState } from "react";

/**
 * Marquee renders a single line of text that scrolls horizontally only when it
 * would otherwise be clipped by its container. Short text stays static. The
 * scroll is a seamless loop (the text is duplicated so it never shows a gap at
 * the wrap), pauses on hover, and is disabled under prefers-reduced-motion.
 *
 * Props:
 *   text     the string to show
 *   title    tooltip (defaults to text) so the full name is always readable
 *   gap      pixels of space between the two copies while scrolling
 *   pxPerSec scroll speed; duration scales with the text width so long and
 *            short names move at the same comfortable pace
 */
export default function Marquee({ text, title, className = "", style, gap = 56, pxPerSec = 38 }) {
  const containerRef = useRef(null);
  const itemRef = useRef(null);
  const [overflow, setOverflow] = useState(false);
  const [contentW, setContentW] = useState(0);

  useEffect(() => {
    const container = containerRef.current;
    const item = itemRef.current;
    if (!container || !item) return undefined;
    const check = () => {
      const cw = container.clientWidth;
      if (cw === 0) return;   // not laid out yet; the ResizeObserver re-fires with a real width
      const tw = item.scrollWidth;   // item carries no padding, so this is the text width
      setContentW(tw);
      setOverflow(tw > cw + 1);
    };
    check();
    const ro = new ResizeObserver(check);
    ro.observe(container);
    ro.observe(item);
    return () => ro.disconnect();
  }, [text]);

  // Seconds for one full loop: proportional to distance so the speed is steady.
  const duration = Math.max(7, (contentW + gap) / pxPerSec);

  return (
    <div
      ref={containerRef}
      className={`marquee ${overflow ? "marquee-animate" : ""} ${className}`}
      style={style}
      title={title ?? text}
    >
      <div
        className="marquee-track"
        style={overflow ? { animationDuration: `${duration}s`, "--marquee-shift": `-${contentW + gap}px` } : undefined}
      >
        <span ref={itemRef} className="marquee-item">{text}</span>
        <span className="marquee-gap" aria-hidden="true" style={{ width: gap }} />
        <span className="marquee-item marquee-dup" aria-hidden="true">{text}</span>
        <span className="marquee-gap marquee-dup" aria-hidden="true" style={{ width: gap }} />
      </div>
    </div>
  );
}
