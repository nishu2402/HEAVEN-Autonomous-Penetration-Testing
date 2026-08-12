// HEAVEN — useChat: shared chat state for the Chat page and the floating widget.
//
// Streams reply tokens over a WebSocket for a live typing effect, and falls back
// to the non-streaming POST /api/chat if the socket can't connect or dies before
// any token arrives. Works with any configured provider (local Ollama /
// OpenAI-compatible / cloud) and can be grounded in the active engagement.

import { useCallback, useRef, useState } from "react";
import { Chat, openChatStream } from "../api";

export function useChat({ engagement, grounded = true } = {}) {
  const [messages, setMessages] = useState([]); // [{role:'user'|'assistant', content}]
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState(null);
  const [meta, setMeta] = useState(null); // {provider, model, grounded}
  const messagesRef = useRef([]);
  const wsRef = useRef(null);
  messagesRef.current = messages;

  const setAssistant = useCallback((updater) => {
    setMessages((cur) => {
      const copy = cur.slice();
      const last = copy[copy.length - 1];
      if (last && last.role === "assistant") {
        copy[copy.length - 1] = { ...last, content: updater(last.content) };
      }
      return copy;
    });
  }, []);

  const dropEmptyAssistant = useCallback(() => {
    setMessages((cur) => {
      const copy = cur.slice();
      const last = copy[copy.length - 1];
      if (last && last.role === "assistant" && !last.content) copy.pop();
      return copy;
    });
  }, []);

  const clear = useCallback(() => {
    if (wsRef.current) { try { wsRef.current.close(); } catch { /* */ } wsRef.current = null; }
    setMessages([]);
    setError(null);
    setStreaming(false);
  }, []);

  const send = useCallback((text) => {
    const clean = String(text || "").trim();
    if (!clean || streaming) return;
    setError(null);
    const outgoing = [...messagesRef.current, { role: "user", content: clean }];
    setMessages([...outgoing, { role: "assistant", content: "" }]);
    setStreaming(true);

    let gotDelta = false;
    let settled = false;
    const finish = () => { setStreaming(false); wsRef.current = null; };

    const fallback = async () => {
      if (settled) return;
      settled = true;
      try {
        const res = await Chat.reply(outgoing, { engagement, grounded });
        if (res && res.skipped) {
          setError(res.skipped);
          dropEmptyAssistant();
        } else {
          setMeta({ provider: res.provider, model: res.model, grounded: res.grounded });
          setAssistant(() => res.reply || "");
          if (!res.reply) { setError("The model returned no text."); dropEmptyAssistant(); }
        }
      } catch (e) {
        setError(String((e && e.message) || e));
        dropEmptyAssistant();
      }
      finish();
    };

    const ws = openChatStream({ messages: outgoing, engagement, grounded }, (frame) => {
      if (!frame || !frame.type) return;
      if (frame.type === "start") {
        setMeta({ provider: frame.provider, model: frame.model, grounded: frame.grounded });
      } else if (frame.type === "delta") {
        gotDelta = true;
        setAssistant((c) => c + (frame.text || ""));
      } else if (frame.type === "skipped") {
        settled = true;
        setError(frame.error || "No LLM configured.");
        dropEmptyAssistant();
        finish();
      } else if (frame.type === "error") {
        if (!gotDelta) { fallback(); }
        else { settled = true; setError(frame.error || "stream error"); finish(); }
      } else if (frame.type === "done") {
        if (!gotDelta && !settled) { fallback(); }
        else { settled = true; finish(); }
      }
    });

    if (!ws) { fallback(); return; }
    wsRef.current = ws;
    ws.onerror = () => { if (!gotDelta && !settled) fallback(); };
    ws.onclose = () => { if (!gotDelta && !settled) fallback(); };
  }, [engagement, grounded, streaming, setAssistant, dropEmptyAssistant]);

  return { messages, streaming, error, meta, send, clear };
}
