// HEAVEN — lightweight, dependency-free Markdown renderer.
//
// The methodology / benchmark docs are our own trusted GitHub-flavoured
// Markdown (headings, alignment-aware pipe tables, lists, links, inline code
// and bold). Rather than pull in react-markdown + remark-gfm (~40 KB), this
// renders exactly those constructs. React escapes all text children, so there
// is no dangerouslySetInnerHTML and no XSS surface.

import React from "react";

// ── Inline: `code`, **bold**, [text](url) ──
function renderInline(text) {
  const nodes = [];
  let rest = String(text);
  let key = 0;
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[[^\]]+\]\([^)]+\))/;
  while (rest) {
    const m = re.exec(rest);
    if (!m) { nodes.push(rest); break; }
    if (m.index > 0) nodes.push(rest.slice(0, m.index));
    const tok = m[0];
    if (tok.startsWith("`")) {
      nodes.push(<code key={key++} className="md-inline-code">{tok.slice(1, -1)}</code>);
    } else if (tok.startsWith("**")) {
      nodes.push(<strong key={key++}>{tok.slice(2, -2)}</strong>);
    } else {
      const lm = /\[([^\]]+)\]\(([^)]+)\)/.exec(tok);
      nodes.push(
        <a key={key++} href={lm[2]} target="_blank" rel="noopener noreferrer"
           style={{ color: "var(--brand)" }}>{lm[1]}</a>
      );
    }
    rest = rest.slice(m.index + tok.length);
  }
  return nodes;
}

function splitRow(line) {
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|")) s = s.slice(0, -1);
  return s.split("|").map((c) => c.trim());
}

const isTableSep = (l) => !!l && l.includes("-") && /^\s*\|?[\s:|-]+\|?\s*$/.test(l);
const isHeading = (l) => /^#{1,6}\s+/.test(l);
const isListItem = (l) => /^\s*[-*]\s+/.test(l);

function parseBlocks(md) {
  const lines = String(md).replace(/\r\n/g, "\n").split("\n");
  const blocks = [];
  let i = 0;
  const startsTable = (idx) =>
    idx + 1 < lines.length && lines[idx].includes("|") && isTableSep(lines[idx + 1]);

  while (i < lines.length) {
    const line = lines[i];
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) { blocks.push({ type: "heading", level: h[1].length, text: h[2] }); i++; continue; }

    if (startsTable(i)) {
      const header = splitRow(line);
      const aligns = splitRow(lines[i + 1]).map((c) => {
        const t = c.trim();
        if (t.startsWith(":") && t.endsWith(":")) return "center";
        if (t.endsWith(":")) return "right";
        return "left";
      });
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) {
        rows.push(splitRow(lines[i])); i++;
      }
      blocks.push({ type: "table", header, aligns, rows });
      continue;
    }

    if (isListItem(line)) {
      const items = [];
      while (i < lines.length && isListItem(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*]\s+/, "")); i++;
      }
      blocks.push({ type: "list", items });
      continue;
    }

    if (!line.trim()) { i++; continue; }

    const para = [line]; i++;
    while (i < lines.length && lines[i].trim()
           && !isHeading(lines[i]) && !isListItem(lines[i]) && !startsTable(i)) {
      para.push(lines[i]); i++;
    }
    blocks.push({ type: "paragraph", text: para.join(" ") });
  }
  return blocks;
}

const HEADING_STYLE = {
  1: { fontSize: 20, fontWeight: 800, margin: "4px 0 12px", color: "var(--text-0)" },
  2: { fontSize: 16, fontWeight: 700, margin: "22px 0 10px", color: "var(--text-0)",
       paddingBottom: 6, borderBottom: "1px solid var(--border)" },
  3: { fontSize: 13.5, fontWeight: 700, margin: "18px 0 8px", color: "var(--brand)",
       textTransform: "none", letterSpacing: 0 },
};

export default function Markdown({ children }) {
  const blocks = parseBlocks(children || "");
  return (
    <div className="md-body" style={{ color: "var(--text-1)", fontSize: 13, lineHeight: 1.65 }}>
      {blocks.map((b, idx) => {
        if (b.type === "heading") {
          const s = HEADING_STYLE[Math.min(b.level, 3)] || HEADING_STYLE[3];
          const Tag = `h${Math.min(b.level, 6)}`;
          return <Tag key={idx} style={s}>{renderInline(b.text)}</Tag>;
        }
        if (b.type === "paragraph") {
          return <p key={idx} style={{ margin: "0 0 12px" }}>{renderInline(b.text)}</p>;
        }
        if (b.type === "list") {
          return (
            <ul key={idx} style={{ margin: "0 0 12px", paddingLeft: 20 }}>
              {b.items.map((it, j) => (
                <li key={j} style={{ margin: "3px 0" }}>{renderInline(it)}</li>
              ))}
            </ul>
          );
        }
        if (b.type === "table") {
          return (
            <div key={idx} style={{ overflowX: "auto", margin: "0 0 16px" }}>
              <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 12.5 }}>
                <thead>
                  <tr>
                    {b.header.map((cell, c) => (
                      <th key={c} style={{
                        textAlign: b.aligns[c] || "left", padding: "8px 12px",
                        background: "var(--bg-1, rgba(255,255,255,0.03))",
                        color: "var(--text-0)", fontWeight: 700,
                        borderBottom: "2px solid var(--border)",
                        whiteSpace: "nowrap", position: "sticky", top: 0,
                      }}>{renderInline(cell)}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {b.rows.map((row, r) => (
                    <tr key={r} style={{
                      background: r % 2 ? "rgba(255,255,255,0.015)" : "transparent",
                    }}>
                      {b.header.map((_, c) => (
                        <td key={c} style={{
                          textAlign: b.aligns[c] || "left", padding: "7px 12px",
                          borderBottom: "1px solid var(--border)",
                          color: "var(--text-1)", verticalAlign: "top",
                        }}>{renderInline(row[c] ?? "")}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        }
        return null;
      })}
    </div>
  );
}
