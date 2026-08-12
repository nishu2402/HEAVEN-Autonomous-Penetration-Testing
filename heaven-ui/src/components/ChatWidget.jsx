// HEAVEN — floating AI assistant widget.
//
// A launcher pinned to the bottom-right of every authenticated page. Opens a
// compact chat panel that shares the same useChat logic + ChatPanel as the full
// Chat page. Grounded in the active engagement by default.

import React, { useState } from "react";
import { Link } from "react-router";
import { useChat } from "../hooks/useChat.js";
import ChatPanel from "./ChatPanel.jsx";

export default function ChatWidget() {
  const [open, setOpen] = useState(false);
  const chat = useChat({ grounded: true });

  return (
    <div className="chat-widget">
      {open && (
        <div className="chat-widget-panel card" role="dialog" aria-label="AI assistant">
          <div className="chat-widget-head">
            <span className="chat-widget-title">✦ AI Assistant</span>
            <div className="chat-widget-actions">
              <Link to="/chat" className="chat-widget-expand" title="Open full page"
                onClick={() => setOpen(false)}>⤢</Link>
              <button type="button" className="chat-widget-close" title="Close"
                onClick={() => setOpen(false)}>✕</button>
            </div>
          </div>
          <ChatPanel chat={chat} compact
            placeholder="Ask the assistant…"
            emptyHint="Hi! Ask me about your findings, a CVE, or how to fix something." />
        </div>
      )}
      <button type="button" className="chat-fab" title="AI assistant"
        aria-label="Open AI assistant" onClick={() => setOpen((v) => !v)}>
        {open ? "✕" : "✦"}
      </button>
    </div>
  );
}
