"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import {
  Scan,
  ShieldAlert,
  AlertTriangle,
  CheckSquare,
  Square,
  ArrowRight,
  Info,
  Server,
  Upload,
  Lock,
  Loader2
} from "lucide-react";
import { createScan } from "@/lib/api";

export default function NewScanPage() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [authAcknowledged, setAuthAcknowledged] = useState(false);
  const [maxPages, setMaxPages] = useState(15);
  const [crawlDepth, setCrawlDepth] = useState(2);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!url.trim()) {
      setError("Please specify a target website URL.");
      return;
    }

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      setError("URL must begin with http:// or https:// scheme.");
      return;
    }

    if (!authAcknowledged) {
      setError("You must acknowledge that you have authorization to scan this target.");
      return;
    }

    setLoading(true);
    try {
      const res = await createScan(url.trim(), authAcknowledged, maxPages, crawlDepth);
      router.push(`/scan/${res.id}`);
    } catch (err: any) {
      setError(err.message || "Failed to start security scan");
      setLoading(false);
    }
  };

  const handleUseDemoTarget = () => {
    setUrl("http://localhost:8001/");
    setAuthAcknowledged(true);
    setError(null);
  };

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      {/* Header */}
      <div>
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-950/80 border border-sky-800/60 text-sky-400 text-xs font-mono mb-2">
          <Scan className="w-3.5 h-3.5" />
          NON-DESTRUCTIVE PASSIVE AUDIT
        </div>
        <h1 className="text-2xl font-black text-white tracking-tight">
          Configure Website Security Scan
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Specify an authorized web domain to evaluate HTTP headers, SSL/TLS transport, cookie flags, and exposed configurations.
        </p>
      </div>

      {/* Main Scan Form */}
      <form onSubmit={handleSubmit} className="bg-cyber-850 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
        {/* Target URL Input */}
        <div className="space-y-2">
          <label className="block text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
            Target Website URL *
          </label>
          <div className="relative">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder-slate-400 font-mono focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500"
            />
          </div>
          <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
            <span>Example: <code>https://example.com</code> or <code>http://localhost:8001/</code></span>
            <button
              type="button"
              onClick={handleUseDemoTarget}
              className="text-sky-400 hover:text-sky-300 font-semibold underline underline-offset-2 flex items-center gap-1"
            >
              <Server className="w-3 h-3" />
              Use Local Test Application (port 8001)
            </button>
          </div>
        </div>

        {/* Crawl Scope Settings */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-slate-800/80">
          <div className="space-y-1.5">
            <label className="block text-xs font-mono text-slate-300">
              Maximum Crawl Pages: <span className="text-sky-400 font-bold">{maxPages}</span>
            </label>
            <input
              type="range"
              min="1"
              max="25"
              value={maxPages}
              onChange={(e) => setMaxPages(parseInt(e.target.value))}
              className="w-full accent-sky-500"
            />
            <span className="text-[11px] text-slate-400">Bounded to max 25 pages for safe execution.</span>
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-mono text-slate-300">
              Crawl Depth: <span className="text-sky-400 font-bold">{crawlDepth}</span>
            </label>
            <input
              type="range"
              min="1"
              max="3"
              value={crawlDepth}
              onChange={(e) => setCrawlDepth(parseInt(e.target.value))}
              className="w-full accent-sky-500"
            />
            <span className="text-[11px] text-slate-400">Depth limit prevents recursive traversal.</span>
          </div>
        </div>

        {/* Source Code / ZIP Upload (Disabled as instructed) */}
        <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 flex items-center justify-between opacity-60">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-slate-800 text-slate-400">
              <Upload className="w-4 h-4" />
            </div>
            <div>
              <span className="text-xs font-semibold text-slate-300">Source Code / ZIP Repository Scan</span>
              <p className="text-[11px] text-slate-400">Direct static application source code inspection</p>
            </div>
          </div>
          <span className="text-[10px] font-mono px-2 py-1 rounded bg-slate-800 border border-slate-700 text-amber-400 font-bold uppercase">
            Coming Soon
          </span>
        </div>

        {/* Legal & Authorization Acknowledgement */}
        <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-900/60 space-y-3">
          <div className="flex items-start space-x-3">
            <button
              type="button"
              onClick={() => setAuthAcknowledged(!authAcknowledged)}
              className="mt-0.5 text-amber-400 hover:text-amber-300 focus:outline-none"
            >
              {authAcknowledged ? (
                <CheckSquare className="w-5 h-5 text-sky-400" />
              ) : (
                <Square className="w-5 h-5 text-slate-400" />
              )}
            </button>
            <div className="text-xs text-slate-300 leading-relaxed">
              <span className="font-bold text-amber-300">Authorization Acknowledgement:</span>
              <p className="mt-0.5 text-slate-400">
                I certify that I am the owner of this target website or have explicit written permission
                from the owner to perform security assessments against this domain.
                (Note: ticking this checkbox acknowledges your responsibility; it does not constitute automated cryptographic proof of ownership).
              </p>
            </div>
          </div>
        </div>

        {/* Error Notification */}
        {error && (
          <div className="p-4 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        {/* Action Button */}
        <button
          type="submit"
          disabled={loading || !authAcknowledged || !url.trim()}
          className="w-full bg-sky-500 hover:bg-sky-400 disabled:opacity-40 disabled:cursor-not-allowed text-slate-950 font-bold text-sm py-3.5 rounded-xl transition-all shadow-lg shadow-sky-500/20 flex items-center justify-center space-x-2"
        >
          {loading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Validating Target and Queuing Scan...</span>
            </>
          ) : (
            <>
              <Scan className="w-4 h-4" />
              <span>Start Security Scan</span>
            </>
          )}
        </button>
      </form>

      {/* Scope and Non-Destructive Guarantee Card */}
      <div className="bg-cyber-850 border border-slate-800 rounded-xl p-5 text-xs text-slate-400 space-y-2">
        <div className="flex items-center space-x-2 font-mono text-slate-300 font-bold text-xs">
          <Info className="w-4 h-4 text-sky-400" />
          <span>SUPPORTED SCAN SCOPE & SAFETY CONTROLS</span>
        </div>
        <ul className="list-disc list-inside space-y-1 text-slate-400 text-[11px] leading-relaxed">
          <li><strong>Outbound Network Controls:</strong> Strict SSRF protection prevents access to cloud metadata (169.254.169.254) and unapproved private subnets.</li>
          <li><strong>Non-Destructive Checks:</strong> Inspects HTTP response headers (CSP, HSTS, X-Frame-Options), TLS certificate dates, cookie flags (HttpOnly, Secure, SameSite), and publicly disclosed server banners.</li>
          <li><strong>Safe Crawling:</strong> Bounded same-origin GET requests only. Never submits forms, modifies state, or guesses passwords.</li>
        </ul>
      </div>
    </div>
  );
}

