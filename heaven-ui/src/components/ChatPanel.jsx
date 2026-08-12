// HEAVEN — shared chat panel (messages + composer). Used by the Chat page and
// the floating ChatWidget so both behave identically. Presentational only; all
// state comes from the useChat hook passed in.

import React, { useEffect, useRef, useState } from "react";
import Markdown from "./Markdown.jsx";

export default function ChatPanel({ chat, placeholder, emptyHint, compact = false }) {
  const { messages, streaming, error, meta, send } = chat;
  const [draft, setDraft] = useState("");
  const scrollRef = useRef(null);

  // Keep the transcript pinned to the newest message as tokens stream in.
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, streaming]);

  function submit() {
    const text = draft.trim();
    if (!text || streaming) return;
    send(text);
    setDraft("");
  }

  function onKeyDown(e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  }

  return (
    <div className={`chat-panel${compact ? " chat-panel--compact" : ""}`}>
      <div className="chat-scroll" ref={scrollRef}>
        {messages.length === 0 && (
          <div className="chat-empty">
            <div className="chat-empty-icon">💬</div>
            <p>{emptyHint || "Ask about your findings, a CVE, an attack chain, or how to fix something."}</p>
            <div className="chat-suggestions">
              {["Summarize my highest-risk findings",
                "What should I fix first and why?",
                "Explain the top finding and how to exploit it (authorized)"]
                .map((s) => (
                  <button key={s} className="chat-chip" type="button"
                    onClick={() => { setDraft(s); }}>{s}</button>
                ))}
            </div>
          </div>
        )}

        {messages.map((m, i) => (
          <div key={i} className={`chat-msg chat-msg--${m.role}`}>
            <div className="chat-bubble">
              {m.role === "assistant"
                ? (m.content
                    ? <Markdown>{m.content}</Markdown>
                    : (streaming
                        ? <span className="chat-typing"><span/><span/><span/></span>
                        : <span className="chat-dim">…</span>))
                : m.content}
            </div>
          </div>
        ))}
      </div>

      {error && <div className="chat-error">{error}</div>}

      <div className="chat-composer">
        <textarea
          className="chat-input"
          rows={compact ? 2 : 3}
          value={draft}
          placeholder={placeholder || "Message the assistant…  (Enter to send, Shift+Enter for a new line)"}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={onKeyDown}
        />
        <button className="btn btn-primary chat-send" type="button"
          onClick={submit} disabled={streaming || !draft.trim()}>
          {streaming ? "…" : "Send"}
        </button>
      </div>

      {meta?.provider && (
        <div className="chat-meta">
          {meta.provider}{meta.model ? ` · ${meta.model}` : ""}
          {meta.grounded ? " · grounded in engagement" : ""}
        </div>
      )}
    </div>
  );
}
