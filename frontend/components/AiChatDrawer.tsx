"use client";

import React, { useState } from "react";
import { Sparkles, X, Send, Bot, User, Loader2, ArrowRight } from "lucide-react";
import { Finding, ChatMessage } from "@/lib/types";
import { sendChatMessage } from "@/lib/api";

interface Props {
  isOpen: boolean;
  onClose: () => void;
  scanId: string;
  finding?: Finding | null;
}

export function AiChatDrawer({ isOpen, onClose, scanId, finding }: Props) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  if (!isOpen) return null;

  const quickPrompts = finding
    ? [
        "Explain this finding simply with an analogy.",
        "Why does this vulnerability matter in production?",
        "Show a safe example of the corrected configuration.",
        "What evidence supports this finding?",
      ]
    : [
        "Which finding should I prioritize fixing first?",
        "Summarize the overall security posture of this scan.",
        "How do I protect against Clickjacking and missing CSP?",
      ];

  const handleSend = async (questionText: string) => {
    if (!questionText.trim() || isLoading) return;

    const userMsg: ChatMessage = {
      sender: "user",
      text: questionText,
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsLoading(true);

    try {
      const response = await sendChatMessage(scanId, questionText, finding?.id);
      const assistantMsg: ChatMessage = {
        sender: "assistant",
        text: response.answer,
        source: response.source,
        model_used: response.model_used,
        suggested_questions: response.suggested_questions,
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        sender: "assistant",
        text: `Error communicating with security assistant: ${err.message || "Unknown error"}`,
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full max-w-lg bg-cyber-900 border-l border-slate-800 shadow-2xl z-50 flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-cyber-850">
        <div className="flex items-center space-x-2.5">
          <div className="w-8 h-8 rounded-lg bg-sky-500/20 border border-sky-400/30 flex items-center justify-center text-sky-400">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
              HACKFIX AI Security Assistant
            </h3>
            <p className="text-[11px] text-slate-400 truncate max-w-[280px]">
              {finding ? `Focus: ${finding.title}` : "Overall Scan Advisory"}
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 && (
          <div className="text-center py-8 space-y-4">
            <div className="w-12 h-12 rounded-full bg-slate-800/80 border border-slate-700 mx-auto flex items-center justify-center text-sky-400">
              <Bot className="w-6 h-6" />
            </div>
            <div>
              <h4 className="text-sm font-semibold text-slate-200">
                {finding ? "Ask about this finding" : "Ask about your security scan"}
              </h4>
              <p className="text-xs text-slate-400 max-w-xs mx-auto mt-1">
                Gemini receives only trusted server-side scan evidence. Untrusted text is strictly sanitized.
              </p>
            </div>

            <div className="space-y-2 text-left pt-2">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
                Suggested Prompts:
              </span>
              {quickPrompts.map((prompt, i) => (
                <button
                  key={i}
                  onClick={() => handleSend(prompt)}
                  className="w-full text-left p-2.5 rounded-lg bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 text-xs text-slate-300 hover:text-sky-300 flex items-center justify-between transition-colors group"
                >
                  <span>{prompt}</span>
                  <ArrowRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity text-sky-400" />
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, index) => (
          <div
            key={index}
            className={`flex flex-col ${msg.sender === "user" ? "items-end" : "items-start"}`}
          >
            <div
              className={`max-w-[90%] rounded-xl p-3.5 text-xs leading-relaxed ${
                msg.sender === "user"
                  ? "bg-sky-500 text-slate-950 font-medium"
                  : "bg-slate-800/90 text-slate-200 border border-slate-700/80"
              }`}
            >
              {msg.sender === "assistant" && (
                <div className="flex items-center justify-between pb-1.5 mb-2 border-b border-slate-700/60 text-[10px] text-slate-400 font-mono">
                  <span>
                    Source: {msg.source === "gemini" ? `Gemini (${msg.model_used || "Flash"})` : "Deterministic Engine"}
                  </span>
                  <span>{msg.timestamp}</span>
                </div>
              )}
              <div className="whitespace-pre-wrap">{msg.text}</div>
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex items-center space-x-2 text-xs text-sky-400 p-2">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Analyzing scan evidence with AI assistant...</span>
          </div>
        )}
      </div>

      {/* Input Form */}
      <div className="p-4 border-t border-slate-800 bg-cyber-850">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend(input);
          }}
          className="flex space-x-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask a question about this vulnerability..."
            className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-sky-500"
          />
          <button
            type="submit"
            disabled={isLoading || !input.trim()}
            className="bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 font-semibold p-2 rounded-lg transition-colors flex items-center justify-center"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
}

