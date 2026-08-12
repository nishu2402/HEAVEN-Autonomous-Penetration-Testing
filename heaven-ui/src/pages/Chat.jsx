// HEAVEN — AI Assistant page.
//
// A grounded security chatbot over the LLM gateway. Works with a local model
// (Ollama / OpenAI-compatible — private, no rate limits) or a cloud key, and can
// answer about the active engagement's findings. Streams replies token-by-token.

import React, { useEffect, useState } from "react";
import { Link } from "react-router";
import { Settings } from "../api";
import { useChat } from "../hooks/useChat.js";
import ChatPanel from "../components/ChatPanel.jsx";

export default function Chat() {
  const [grounded, setGrounded] = useState(true);
  const [local, setLocal] = useState(null);       // aiLocalStatus()
  const chat = useChat({ grounded });

  useEffect(() => {
    Settings.aiLocalStatus().then(setLocal).catch(() => setLocal(null));
  }, []);

  const localReady = local && (local.reachable && (local.models || []).length > 0);
  const showSetupHint = local && local.provider === "ollama" && !localReady;

  return (
    <div className="page">
      <div className="page-head" style={{ display: "flex", justifyContent: "space-between",
        alignItems: "flex-start", gap: 12, flexWrap: "wrap" }}>
        <div>
          <h1>AI Assistant</h1>
          <p className="muted" style={{ margin: "4px 0 0" }}>
            Ask about your findings, CVEs, attack chains, and fixes. Runs on your
            configured model — a local one keeps everything private and rate-limit-free.
          </p>
        </div>
        <label className="chat-toggle" title="Feed the active engagement's findings to the assistant">
          <input type="checkbox" checked={grounded}
            onChange={(e) => setGrounded(e.target.checked)} />
          <span>Ground in engagement</span>
        </label>
      </div>

      {showSetupHint && (
        <div className="card chat-setup-hint">
          <strong>💡 Set up a free local model</strong> — no API key, no rate limits.
          Run <code>heaven ai setup</code> in your terminal (installs Ollama +
          pulls <code>{local.default_model}</code>), or configure a provider in{" "}
          <Link to="/settings">Settings</Link>.
        </div>
      )}

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <ChatPanel chat={chat} />
      </div>

      <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
        <button className="btn btn-ghost btn-small" type="button" onClick={chat.clear}>
          Clear conversation
        </button>
      </div>
    </div>
  );
}
