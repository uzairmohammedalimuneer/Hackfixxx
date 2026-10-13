"use client";

import React, { useState } from "react";
import { X, RefreshCw, CheckCircle2, XCircle, AlertTriangle, HelpCircle, Loader2 } from "lucide-react";
import { Finding, RetestResult } from "@/lib/types";
import { retestFinding } from "@/lib/api";

interface Props {
  isOpen: boolean;
  onClose: () => void;
  finding: Finding;
  onRetestComplete?: (result: RetestResult) => void;
}

export function RetestModal({ isOpen, onClose, finding, onRetestComplete }: Props) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<RetestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleRunRetest = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await retestFinding(finding.id);
      setResult(res);
      if (onRetestComplete) {
        onRetestComplete(res);
      }
    } catch (err: any) {
      setError(err.message || "Retest execution failed");
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "verified_fixed":
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-950 text-emerald-400 border border-emerald-700">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            VERIFIED FIXED
          </span>
        );
      case "still_present":
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-red-950 text-red-400 border border-red-700">
            <XCircle className="w-4 h-4 text-red-400" />
            STILL PRESENT
          </span>
        );
      case "inconclusive":
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-amber-950 text-amber-400 border border-amber-700">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            INCONCLUSIVE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-slate-800 text-slate-300 border border-slate-700">
            <HelpCircle className="w-4 h-4 text-slate-400" />
            NOT SUPPORTED
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-cyber-900 border border-slate-800 rounded-xl w-full max-w-2xl overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 bg-cyber-850 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-sky-500/20 border border-sky-400/30 flex items-center justify-center text-sky-400">
              <RefreshCw className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100">
                Evidence-Based Retest
              </h3>
              <p className="text-xs text-slate-400 truncate max-w-md">
                {finding.title}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1 rounded hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5">
          <div className="bg-slate-900/60 p-3.5 rounded-lg border border-slate-800 text-xs space-y-1">
            <div className="text-slate-400 font-mono text-[11px]">TARGET URL:</div>
            <div className="text-slate-200 font-mono break-all">{finding.affected_url}</div>
          </div>

          {/* Evidence Comparison Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            {/* Previous Evidence */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 space-y-2">
              <div className="font-semibold text-slate-300 flex items-center justify-between">
                <span>Baseline Observation</span>
                <span className="text-[10px] text-slate-400 font-mono">Original</span>
              </div>
              <pre className="p-2.5 rounded bg-slate-950 text-slate-300 font-mono text-[11px] overflow-x-auto max-h-48">
                {JSON.stringify(finding.evidence || {}, null, 2)}
              </pre>
            </div>

            {/* New Evidence */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 space-y-2">
              <div className="font-semibold text-slate-300 flex items-center justify-between">
                <span>Retest Observation</span>
                <span className="text-[10px] text-slate-400 font-mono">New Request</span>
              </div>
              {result ? (
                <pre className="p-2.5 rounded bg-slate-950 text-sky-300 font-mono text-[11px] overflow-x-auto max-h-48">
                  {JSON.stringify(result.new_evidence || {}, null, 2)}
                </pre>
              ) : (
                <div className="h-32 flex flex-col items-center justify-center text-slate-400 border border-dashed border-slate-800 rounded">
                  <p>Click "Run Retest" below to repeat the check.</p>
                </div>
              )}
            </div>
          </div>

          {/* Result Banner */}
          {result && (
            <div className="p-4 rounded-lg bg-cyber-850 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">VERIFICATION OUTCOME:</span>
                {getStatusBadge(result.status)}
              </div>
              <p className="text-xs text-slate-300">{result.details}</p>
              <div className="text-[10px] font-mono text-slate-400">
                Timestamp: {new Date(result.timestamp).toLocaleString()}
              </div>
            </div>
          )}

          {error && (
            <div className="p-3 bg-red-950/60 border border-red-800 text-red-300 text-xs rounded-lg">
              {error}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-cyber-850 flex items-center justify-between">
          <p className="text-[11px] text-slate-400">
            * Retest repeats non-destructive passive checks against the authorized target.
          </p>
          <div className="flex space-x-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              Close
            </button>
            <button
              onClick={handleRunRetest}
              disabled={loading}
              className="bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 font-bold text-xs px-4 py-2 rounded-lg transition-colors flex items-center space-x-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Auditing Target...</span>
                </>
              ) : (
                <>
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Run Retest</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

