import React, { useState, useEffect, useRef } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { login } from "../api";

const LINES = [
  "> initializing HEAVEN security framework...",
  "> loading threat intelligence modules...",
  "> establishing encrypted channel...",
  "> autonomous recon engine ready",
  "> awaiting operator authentication",
];

function MatrixRain({ canvasRef }) {
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    resize();
    window.addEventListener("resize", resize);

    const cols = Math.floor(canvas.width / 16);
    const drops = Array(cols).fill(1);
    const chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワン";

    const draw = () => {
      ctx.fillStyle = "rgba(0,0,0,0.05)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "rgba(0,255,65,0.18)";
      ctx.font = "13px monospace";
      drops.forEach((y, i) => {
        const ch = chars[Math.floor(Math.random() * chars.length)];
        ctx.fillText(ch, i * 16, y * 16);
        if (y * 16 > canvas.height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      });
    };
    const id = setInterval(draw, 50);
    return () => { clearInterval(id); window.removeEventListener("resize", resize); };
  }, []);
  return <canvas ref={canvasRef} style={{ position: "fixed", inset: 0, zIndex: 0, opacity: 0.4 }} />;
}

function BootSequence({ onDone }) {
  const [lines, setLines] = useState([]);
  const [done, setDone] = useState(false);

  useEffect(() => {
    let i = 0;
    const next = () => {
      if (i >= LINES.length) { setTimeout(() => { setDone(true); onDone(); }, 300); return; }
      setLines(prev => [...prev, LINES[i++]]);
      setTimeout(next, 380 + Math.random() * 200);
    };
    const t = setTimeout(next, 200);
    return () => clearTimeout(t);
  }, []);

  if (done) return null;
  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 10, background: "#000",
      display: "flex", alignItems: "center", justifyContent: "center",
    }}>
      <div style={{ fontFamily: "monospace", fontSize: 13, color: "#00FF41", maxWidth: 500, width: "100%", padding: 24 }}>
        <div style={{ fontSize: 22, fontWeight: 700, color: "#00FF41", marginBottom: 20, letterSpacing: "0.15em",
                      textShadow: "0 0 20px #00FF41" }}>
          ⚡ HEAVEN
        </div>
        {lines.map((l, i) => (
          <div key={i} style={{ marginBottom: 6, opacity: 0.85 }}>
            <span style={{ color: "rgba(0,255,65,0.4)" }}>{l.slice(0, 2)}</span>
            <span style={{ color: "#00FF41" }}>{l.slice(2)}</span>
          </div>
        ))}
        <span style={{ color: "#00FF41", animation: "blink 1s step-end infinite" }}>█</span>
      </div>
    </div>
  );
}

export default function LoginPage() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [ready, setReady] = useState(false);
  const [focusField, setFocusField] = useState(null);
  const canvasRef = useRef(null);
  const navigate = useNavigate();
  const loc = useLocation();
  const dest = loc.state?.from?.pathname || "/";

  async function submit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await login(username, password);
      navigate(dest, { replace: true });
    } catch (err) {
      setError(err.message || "Authentication failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <MatrixRain canvasRef={canvasRef} />
      {!ready && <BootSequence onDone={() => setReady(true)} />}

      <div style={{
        position: "fixed", inset: 0, zIndex: 5,
        display: "flex", alignItems: "center", justifyContent: "center",
        opacity: ready ? 1 : 0, transition: "opacity 0.6s ease",
        padding: 20,
      }}>
        <form onSubmit={submit} style={{
          width: "100%", maxWidth: 420,
          background: "rgba(0,0,0,0.88)",
          border: "1px solid rgba(0,255,65,0.35)",
          boxShadow: "0 0 40px rgba(0,255,65,0.12), inset 0 0 40px rgba(0,0,0,0.5)",
          padding: "40px 36px",
          position: "relative",
          backdropFilter: "blur(12px)",
        }}>
          {/* Corner accents */}
          {["top:0;left:0;border-top:2px solid #00FF41;border-left:2px solid #00FF41",
            "top:0;right:0;border-top:2px solid #00FF41;border-right:2px solid #00FF41",
            "bottom:0;left:0;border-bottom:2px solid #00FF41;border-left:2px solid #00FF41",
            "bottom:0;right:0;border-bottom:2px solid #00FF41;border-right:2px solid #00FF41",
          ].map((s, i) => (
            <div key={i} style={{
              position: "absolute", width: 16, height: 16,
              ...Object.fromEntries(s.split(";").map(p => {
                const [k, v] = p.split(":");
                return [k.replace(/-([a-z])/g, (_, c) => c.toUpperCase()), v];
              })),
            }} />
          ))}

          {/* Brand */}
          <div style={{ textAlign: "center", marginBottom: 32 }}>
            <div style={{
              fontSize: 36, fontWeight: 900, letterSpacing: "0.2em",
              color: "#00FF41", textShadow: "0 0 30px rgba(0,255,65,0.8), 0 0 60px rgba(0,255,65,0.4)",
              fontFamily: "monospace",
            }}>⚡ HEAVEN</div>
            <div style={{
              fontSize: 11, color: "rgba(0,255,65,0.68)", letterSpacing: "0.35em",
              marginTop: 6, textTransform: "uppercase",
            }}>
              Autonomous Penetration Testing
            </div>
            <div style={{ marginTop: 12, height: 1, background: "linear-gradient(90deg, transparent, rgba(0,255,65,0.3), transparent)" }} />
          </div>

          {/* Status bar */}
          <div style={{
            fontSize: 11, color: "rgba(0,255,65,0.62)", letterSpacing: "0.15em",
            marginBottom: 24, fontFamily: "monospace",
          }}>
            OPERATOR AUTH REQUIRED · AES-256 ENCRYPTED SESSION
          </div>

          {/* Username */}
          <div style={{ marginBottom: 16 }}>
            <div style={{
              fontSize: 11, color: "rgba(0,255,65,0.72)", letterSpacing: "0.2em",
              marginBottom: 6, fontFamily: "monospace",
            }}>OPERATOR ID</div>
            <div style={{
              display: "flex", alignItems: "center",
              border: `1px solid ${focusField === "user" ? "rgba(0,255,65,0.6)" : "rgba(0,255,65,0.2)"}`,
              background: "rgba(0,255,65,0.03)",
              transition: "border-color 0.2s",
              boxShadow: focusField === "user" ? "0 0 12px rgba(0,255,65,0.1)" : "none",
            }}>
              <span style={{ padding: "0 10px", color: "rgba(0,255,65,0.4)", fontSize: 12 }}>›</span>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                onFocus={() => setFocusField("user")}
                onBlur={() => setFocusField(null)}
                autoFocus
                autoComplete="username"
                style={{
                  flex: 1, background: "transparent", border: "none", outline: "none",
                  color: "#00FF41", fontFamily: "monospace", fontSize: 13,
                  padding: "10px 10px 10px 0",
                }}
              />
            </div>
          </div>

          {/* Password */}
          <div style={{ marginBottom: 24 }}>
            <div style={{
              fontSize: 11, color: "rgba(0,255,65,0.72)", letterSpacing: "0.2em",
              marginBottom: 6, fontFamily: "monospace",
            }}>ACCESS KEY</div>
            <div style={{
              display: "flex", alignItems: "center",
              border: `1px solid ${focusField === "pass" ? "rgba(0,255,65,0.6)" : "rgba(0,255,65,0.2)"}`,
              background: "rgba(0,255,65,0.03)",
              transition: "border-color 0.2s",
              boxShadow: focusField === "pass" ? "0 0 12px rgba(0,255,65,0.1)" : "none",
            }}>
              <span style={{ padding: "0 10px", color: "rgba(0,255,65,0.4)", fontSize: 12 }}>⬡</span>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                onFocus={() => setFocusField("pass")}
                onBlur={() => setFocusField(null)}
                autoComplete="current-password"
                required
                style={{
                  flex: 1, background: "transparent", border: "none", outline: "none",
                  color: "#00FF41", fontFamily: "monospace", fontSize: 13,
                  padding: "10px 10px 10px 0", letterSpacing: "0.15em",
                }}
              />
            </div>
          </div>

          {/* Error */}
          {error && (
            <div style={{
              marginBottom: 16, padding: "8px 12px",
              background: "rgba(255,0,60,0.08)", border: "1px solid rgba(255,0,60,0.3)",
              color: "#FF003C", fontSize: 11, fontFamily: "monospace",
            }}>
              ✗ {error}
            </div>
          )}

          {/* Submit */}
          <button
            type="submit"
            disabled={busy}
            style={{
              width: "100%", padding: "12px",
              background: busy ? "rgba(0,255,65,0.05)" : "rgba(0,255,65,0.08)",
              border: "1px solid rgba(0,255,65,0.5)",
              color: "#00FF41", fontFamily: "monospace", fontSize: 12,
              letterSpacing: "0.2em", cursor: busy ? "not-allowed" : "pointer",
              textTransform: "uppercase", fontWeight: 700,
              boxShadow: busy ? "none" : "0 0 20px rgba(0,255,65,0.1)",
              transition: "all 0.2s",
            }}
            onMouseEnter={e => { if (!busy) e.target.style.background = "rgba(0,255,65,0.15)"; }}
            onMouseLeave={e => { e.target.style.background = busy ? "rgba(0,255,65,0.05)" : "rgba(0,255,65,0.08)"; }}
          >
            {busy ? (
              <span>
                <span style={{ animation: "blink 0.8s step-end infinite" }}>▋</span>
                {" "}AUTHENTICATING...
              </span>
            ) : "[ AUTHENTICATE ]"}
          </button>

          {/* Hint */}
          <div style={{
            marginTop: 20, fontSize: 11, color: "rgba(0,255,65,0.58)",
            fontFamily: "monospace", textAlign: "center", lineHeight: 1.6,
          }}>
            Set HEAVEN_ADMIN_PASSWORD on the server to configure access credentials.
            <br />All sessions are HMAC-audited and AES-256 encrypted.
          </div>
        </form>
      </div>
    </>
  );
}
