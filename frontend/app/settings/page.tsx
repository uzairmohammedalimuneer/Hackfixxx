"use client";

import React, { useEffect, useState } from "react";
import { Settings, ShieldCheck, Sparkles, Lock, Cpu, Server, CheckCircle2, AlertCircle, RefreshCw } from "lucide-react";
import { getHealth } from "@/lib/api";
import { SystemHealth } from "@/lib/types";

export default function SettingsPage() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchStatus = () => {
    setLoading(true);
    getHealth()
      .then(setHealth)
      .catch(() => setHealth(null))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-950/80 border border-sky-800/60 text-sky-400 text-xs font-mono mb-2">
            <Settings className="w-3.5 h-3.5" />
            ENGINE CONFIGURATION & CAPABILITIES
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight">
            System Status & Configuration
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Overview of scanner engine runtimes, AI services, network safety controls, and optional scanner plugins.
          </p>
        </div>

        <button
          onClick={fetchStatus}
          className="bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 px-3.5 py-2 rounded-xl text-xs font-semibold flex items-center space-x-1.5 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Status</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Core Scanner Engine */}
        <div className="bg-cyber-850 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center space-x-2.5">
            <Cpu className="w-5 h-5 text-sky-400" />
            <h3 className="text-sm font-bold text-slate-200">Native Python Scanner Engine</h3>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Performs non-destructive HTTP headers analysis, TLS certificate validation, cookie security flags,
            and bounded same-origin crawling.
          </p>
          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">STATUS:</span>
            <span className="text-emerald-400 font-bold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> ONLINE (v{health?.version || "1.0.0"})
            </span>
          </div>
        </div>

        {/* Gemini AI Integration */}
        <div className="bg-cyber-850 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center space-x-2.5">
            <Sparkles className="w-5 h-5 text-sky-400" />
            <h3 className="text-sm font-bold text-slate-200">Google Gemini Integration</h3>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Transforms technical scanner evidence into beginner-friendly explanations and contextual security chat.
            Falls back cleanly to deterministic guidance when API key is unconfigured.
          </p>
          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">STATUS:</span>
            <span
              className={`font-bold flex items-center gap-1 ${
                health?.capabilities?.gemini_ai?.configured ? "text-emerald-400" : "text-amber-400"
              }`}
            >
              {health?.capabilities?.gemini_ai?.configured ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5" /> Configured ({health.capabilities.gemini_ai.model})
                </>
              ) : (
                <>
                  <AlertCircle className="w-3.5 h-3.5" /> Fallback Engine Active (No API Key)
                </>
              )}
            </span>
          </div>
        </div>

        {/* SSRF Outbound Controls */}
        <div className="bg-cyber-850 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center space-x-2.5">
            <Lock className="w-5 h-5 text-emerald-400" />
            <h3 className="text-sm font-bold text-slate-200">SSRF & Egress Boundary Protection</h3>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Validates hostname resolution and revalidates every HTTP redirect hop.
            Blocks loopback, link-local, private subnets, and cloud metadata (169.254.169.254) by default.
          </p>
          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">DEFENSE STATUS:</span>
            <span className="text-emerald-400 font-bold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> ENFORCED (Active)
            </span>
          </div>
        </div>

        {/* OWASP ZAP Baseline */}
        <div className="bg-cyber-850 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center space-x-2.5">
            <ShieldCheck className="w-5 h-5 text-slate-400" />
            <h3 className="text-sm font-bold text-slate-200">OWASP ZAP Baseline Integration</h3>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Optional secondary crawler and passive analyzer. Disabled by default to ensure zero-dependency local startup.
          </p>
          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">STATUS:</span>
            <span className="text-slate-400 font-bold">
              {health?.capabilities?.owasp_zap?.enabled ? "Enabled" : "Disabled (ZAP_ENABLED=false)"}
            </span>
          </div>
        </div>
      </div>

      {/* Local Environment Configuration Instructions */}
      <div className="bg-cyber-850 border border-slate-800 rounded-xl p-6 text-xs text-slate-300 space-y-3">
        <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
          <Server className="w-4 h-4 text-sky-400" />
          Configuring Your Gemini API Key Securely
        </h3>
        <p className="text-slate-400 leading-relaxed">
          To enable live Gemini explanations, add your key to <code>backend/.env</code>:
        </p>
        <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-sky-300 font-mono text-[11px]">
GEMINI_API_KEY="your-google-genai-api-key"
GEMINI_MODEL="gemini-2.5-flash"
GEMINI_ENABLED=true
        </pre>
        <p className="text-slate-400">
          The backend automatically reads this file without exposing keys to frontend client code or network payloads.
        </p>
      </div>
    </div>
  );
}

