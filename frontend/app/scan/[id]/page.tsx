"use client";

import React, { useEffect, useState, useRef } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  Scan,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Terminal,
  Clock,
  Sparkles,
  RefreshCw,
  FileDown,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Loader2,
  ArrowRight
} from "lucide-react";
import { getScan, getPdfReportUrl, getHtmlReportUrl } from "@/lib/api";
import { ScanDetail, Finding, ScanStage } from "@/lib/types";
import { SeverityBadge } from "@/components/SeverityBadge";
import { OwaspCoverageTable } from "@/components/OwaspCoverageTable";
import { AiChatDrawer } from "@/components/AiChatDrawer";
import { RetestModal } from "@/components/RetestModal";

export default function LiveScanDetailPage() {
  const params = useParams();
  const scanId = params.id as string;

  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Expanded cards state
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  // Filter & Search
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // AI Chat & Retest Modals
  const [chatOpen, setChatOpen] = useState(false);
  const [chatFocusedFinding, setChatFocusedFinding] = useState<Finding | null>(null);
  const [retestModalFinding, setRetestModalFinding] = useState<Finding | null>(null);

  // Poll for scan status until complete or failed
  useEffect(() => {
    let interval: NodeJS.Timeout;

    const fetchScanData = async () => {
      try {
        const data = await getScan(scanId);
        setScan(data);
        setLoading(false);

        // If scan finished, stop polling
        if (data.status === "completed" || data.status === "failed" || data.status === "cancelled") {
          clearInterval(interval);
        }
      } catch (err: any) {
        setError(err.message || "Failed to load scan");
        setLoading(false);
        clearInterval(interval);
      }
    };

    fetchScanData();
    interval = setInterval(fetchScanData, 2000);

    return () => clearInterval(interval);
  }, [scanId]);

  const toggleFindingExpand = (id: string) => {
    setExpandedFindings((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const stages: { stage: ScanStage; label: string; desc: string }[] = [
    { stage: "FIND", label: "FIND", desc: "Discover endpoints, headers, and certificates" },
    { stage: "PROVE", label: "PROVE", desc: "Collect and evaluate concrete HTTP evidence" },
    { stage: "FIX", label: "FIX", desc: "Synthesize remediation and Gemini guidance" },
    { stage: "VERIFY", label: "VERIFY", desc: "Set verification baseline for retesting" },
  ];

  const getStageStatus = (stageName: ScanStage) => {
    if (!scan) return "pending";
    if (scan.status === "failed") return "failed";

    const stageOrder: ScanStage[] = ["QUEUED", "FIND", "PROVE", "FIX", "VERIFY", "COMPLETED"];
    const currentIndex = stageOrder.indexOf(scan.stage);
    const targetIndex = stageOrder.indexOf(stageName);

    if (scan.status === "completed") return "completed";
    if (currentIndex > targetIndex) return "completed";
    if (currentIndex === targetIndex) return "active";
    return "pending";
  };

  const filteredFindings = (scan?.findings || []).filter((f) => {
    const matchesSev = severityFilter === "ALL" || f.severity.toUpperCase() === severityFilter;
    const matchesSearch =
      !searchQuery ||
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.affected_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.owasp_category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  });

  if (loading && !scan) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <Loader2 className="w-8 h-8 text-sky-400 animate-spin" />
        <p className="text-sm text-slate-400 font-mono">Loading scan records from database...</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="max-w-2xl mx-auto p-8 bg-red-950/40 border border-red-800 rounded-2xl text-center space-y-4">
        <AlertTriangle className="w-10 h-10 text-red-400 mx-auto" />
        <h2 className="text-lg font-bold text-slate-100">Scan Unavailable</h2>
        <p className="text-xs text-red-300 font-mono">{error || "Scan not found"}</p>
        <Link
          href="/history"
          className="inline-flex items-center space-x-2 bg-slate-800 text-slate-200 text-xs px-4 py-2 rounded-lg"
        >
          <span>Return to Scan History</span>
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      {/* Scan Header Bar */}
      <div className="bg-cyber-850 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex items-center space-x-3">
            <span
              className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold tracking-wider ${
                scan.status === "completed"
                  ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                  : scan.status === "running"
                  ? "bg-sky-950 text-sky-400 border border-sky-800 animate-pulse"
                  : "bg-red-950 text-red-400 border border-red-800"
              }`}
            >
              {scan.status.toUpperCase()}
            </span>
            <span className="text-xs text-slate-400 font-mono">ID: {scan.id.slice(0, 8)}...</span>
          </div>
          <h1 className="text-xl font-black text-white font-mono break-all">
            {scan.target_url}
          </h1>
          <p className="text-xs text-slate-400 flex items-center gap-3">
            <span>Created: {new Date(scan.created_at).toLocaleString()}</span>
            {scan.summary?.duration_seconds > 0 && (
              <span>Duration: {scan.summary.duration_seconds}s</span>
            )}
            {scan.summary?.pages_scanned > 0 && (
              <span>Pages Audited: {scan.summary.pages_scanned}</span>
            )}
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => {
              setChatFocusedFinding(null);
              setChatOpen(true);
            }}
            className="inline-flex items-center space-x-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs px-3.5 py-2.5 rounded-xl transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5 text-sky-400" />
            <span>AI Security Advisor</span>
          </button>

          {scan.status === "completed" && (
            <a
              href={getPdfReportUrl(scan.id)}
              download
              className="inline-flex items-center space-x-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-xs px-4 py-2.5 rounded-xl transition-all shadow-md shadow-sky-500/20"
            >
              <FileDown className="w-4 h-4" />
              <span>Download PDF Report</span>
            </a>
          )}
        </div>
      </div>

      {/* Honest 4-Stage Pipeline Progress (FIND -> PROVE -> FIX -> VERIFY) */}
      <div className="bg-cyber-850 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <Clock className="w-4 h-4 text-sky-400" />
            Audit Pipeline Stages (Honest State Machine)
          </h2>
          <span className="text-xs font-mono text-sky-400 font-semibold">
            Current Stage: [{scan.stage}]
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
          {stages.map((st, i) => {
            const status = getStageStatus(st.stage);
            return (
              <div
                key={st.stage}
                className={`p-4 rounded-xl border transition-all ${
                  status === "active"
                    ? "bg-sky-950/60 border-sky-500 text-sky-200 shadow-lg shadow-sky-950"
                    : status === "completed"
                    ? "bg-slate-900 border-slate-700/80 text-slate-200"
                    : "bg-slate-900/40 border-slate-800 text-slate-400 opacity-60"
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-mono font-extrabold flex items-center gap-1.5">
                    {status === "completed" && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
                    {status === "active" && <Loader2 className="w-3.5 h-3.5 text-sky-400 animate-spin" />}
                    {status === "pending" && <span className="w-3.5 h-3.5 rounded-full border border-slate-600 inline-block text-center text-[9px] leading-3">{i+1}</span>}
                    {st.label}
                  </span>
                  <span className="text-[10px] font-mono uppercase text-slate-400">
                    {status}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-snug">
                  {st.desc}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Live Timestamped Terminal Logs */}
      <div className="bg-cyber-850 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 bg-slate-900/80 flex items-center justify-between">
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-300">
            <Terminal className="w-4 h-4 text-sky-400" />
            <span className="font-bold">LIVE TIMESTAMPED AUDIT LOGS</span>
          </div>
          <span className="text-[10px] font-mono text-slate-400">
            {scan.logs?.length || 0} events recorded
          </span>
        </div>
        <div className="p-4 bg-slate-950 max-h-48 overflow-y-auto font-mono text-[11px] space-y-1.5 text-slate-300">
          {(!scan.logs || scan.logs.length === 0) ? (
            <div className="text-slate-400 italic">Awaiting scanner events...</div>
          ) : (
            scan.logs.map((log) => (
              <div key={log.id} className="flex items-start space-x-2.5">
                <span className="text-slate-400 flex-shrink-0">
                  [{new Date(log.timestamp).toLocaleTimeString()}]
                </span>
                <span
                  className={`font-semibold flex-shrink-0 ${
                    log.level === "ERROR"
                      ? "text-red-400"
                      : log.level === "WARNING"
                      ? "text-amber-400"
                      : "text-sky-400"
                  }`}
                >
                  [{log.stage}]
                </span>
                <span className="text-slate-300 break-all">{log.message}</span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Findings Section */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-black text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-sky-400" />
              Observed Security Findings ({scan.findings?.length || 0})
            </h2>
            <p className="text-xs text-slate-400">
              Each finding presents concrete observed HTTP metadata, impact, and verification status.
            </p>
          </div>

          {/* Filter & Search Bar */}
          <div className="flex items-center space-x-2">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search findings..."
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-sky-500"
            />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFORMATIONAL">Informational</option>
            </select>
          </div>
        </div>

        {/* Findings List */}
        {filteredFindings.length === 0 ? (
          <div className="bg-cyber-850 border border-slate-800 rounded-2xl p-12 text-center text-slate-400 space-y-2">
            <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
            <h3 className="text-sm font-bold text-slate-200">
              {scan.status === "completed" ? "No Matching Findings Detected" : "Scanning Target..."}
            </h3>
            <p className="text-xs max-w-md mx-auto">
              {scan.status === "completed"
                ? "The configured non-destructive passive checks observed no anomalies matching your filter."
                : "Security checks are currently probing headers, certificates, and endpoints in real-time."}
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredFindings.map((finding) => {
              const isExpanded = !!expandedFindings[finding.id];
              return (
                <div
                  key={finding.id}
                  className="bg-cyber-850 border border-slate-800 rounded-xl overflow-hidden shadow-sm transition-all"
                >
                  {/* Card Header / Summary Row */}
                  <div
                    onClick={() => toggleFindingExpand(finding.id)}
                    className="p-4 flex items-center justify-between cursor-pointer hover:bg-slate-800/40 transition-colors"
                  >
                    <div className="flex items-center space-x-3.5 flex-1 min-w-0 pr-4">
                      <SeverityBadge severity={finding.severity} size="sm" />
                      <div className="min-w-0">
                        <h4 className="text-sm font-bold text-slate-100 truncate">
                          {finding.title}
                        </h4>
                        <div className="flex items-center space-x-3 text-[11px] text-slate-400 mt-0.5 font-mono">
                          <span className="text-sky-400">{finding.owasp_category}</span>
                          <span>•</span>
                          <span className="truncate max-w-xs">{finding.affected_url}</span>
                          <span>•</span>
                          <span className="text-slate-400">
                            Status: {finding.verification_status}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center space-x-2 flex-shrink-0">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setRetestModalFinding(finding);
                        }}
                        className="bg-slate-800 hover:bg-slate-700 text-sky-400 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-colors"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span>Retest Fix</span>
                      </button>

                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setChatFocusedFinding(finding);
                          setChatOpen(true);
                        }}
                        className="bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border border-sky-500/30 px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-colors"
                      >
                        <Sparkles className="w-3.5 h-3.5" />
                        <span>Ask AI</span>
                      </button>

                      <button className="text-slate-400 p-1">
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Expandable Finding Details */}
                  {isExpanded && (
                    <div className="p-5 border-t border-slate-800/80 bg-slate-900/50 space-y-4 text-xs">
                      {/* Beginner Explanation / AI Callout */}
                      {finding.beginner_explanation && (
                        <div className="p-3.5 rounded-lg bg-sky-950/40 border border-sky-800/60 space-y-1">
                          <div className="font-semibold text-sky-300 flex items-center gap-1.5 font-mono text-[11px]">
                            <Sparkles className="w-3.5 h-3.5 text-sky-400" />
                            BEGINNER-FRIENDLY EXPLANATION
                          </div>
                          <p className="text-slate-300 leading-relaxed">
                            {finding.beginner_explanation}
                          </p>
                        </div>
                      )}

                      {/* Technical Description & Impact */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-1">
                          <span className="font-mono text-slate-400 text-[11px] uppercase">
                            What Was Observed:
                          </span>
                          <p className="text-slate-300 leading-relaxed">
                            {finding.description}
                          </p>
                        </div>

                        <div className="space-y-1">
                          <span className="font-mono text-slate-400 text-[11px] uppercase">
                            Potential Risk & Impact:
                          </span>
                          <p className="text-slate-300 leading-relaxed">
                            {finding.impact}
                          </p>
                        </div>
                      </div>

                      {/* Evidence Metadata Block */}
                      <div className="space-y-1">
                        <span className="font-mono text-slate-400 text-[11px] uppercase">
                          Observed HTTP Evidence & Metadata:
                        </span>
                        <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-40">
                          {JSON.stringify(finding.evidence || {}, null, 2)}
                        </pre>
                      </div>

                      {/* Recommended Fix and Code Diff */}
                      <div className="space-y-2">
                        <span className="font-mono text-slate-400 text-[11px] uppercase">
                          Recommended Remediation:
                        </span>
                        <p className="text-slate-300 leading-relaxed font-semibold">
                          {finding.recommended_fix}
                        </p>

                        {finding.example_after && (
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                            {finding.example_before && (
                              <div>
                                <span className="text-[10px] font-mono text-red-400 uppercase">
                                  Before (Vulnerable Configuration):
                                </span>
                                <pre className="p-2.5 rounded bg-slate-950 border border-red-900/60 font-mono text-[11px] text-red-300 overflow-x-auto">
                                  {finding.example_before}
                                </pre>
                              </div>
                            )}
                            <div>
                              <span className="text-[10px] font-mono text-emerald-400 uppercase">
                                After (Hardened Configuration):
                              </span>
                              <pre className="p-2.5 rounded bg-slate-950 border border-emerald-900/60 font-mono text-[11px] text-emerald-300 overflow-x-auto">
                                {finding.example_after}
                              </pre>
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Limitations and Scope Note */}
                      {finding.limitations && (
                        <div className="p-2.5 rounded bg-slate-800/40 border border-slate-800 text-[11px] text-slate-400 italic">
                          <strong>Assessment Limitation:</strong> {finding.limitations}
                        </div>
                      )}

                      {/* References */}
                      {finding.references?.length > 0 && (
                        <div className="pt-1">
                          <span className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                            References:
                          </span>
                          <div className="flex flex-wrap gap-2">
                            {finding.references.map((ref, idx) => (
                              <a
                                key={idx}
                                href={ref}
                                target="_blank"
                                rel="noreferrer"
                                className="text-[11px] text-sky-400 hover:underline flex items-center gap-1"
                              >
                                <span>{ref}</span>
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* OWASP Coverage Table Component */}
      {scan.summary?.owasp_coverage && (
        <OwaspCoverageTable coverage={scan.summary.owasp_coverage} />
      )}

      {/* AI Security Assistant Drawer */}
      <AiChatDrawer
        isOpen={chatOpen}
        onClose={() => setChatOpen(false)}
        scanId={scan.id}
        finding={chatFocusedFinding}
      />

      {/* Retest Modal */}
      {retestModalFinding && (
        <RetestModal
          isOpen={true}
          onClose={() => setRetestModalFinding(null)}
          finding={retestModalFinding}
          onRetestComplete={(res) => {
            // Update local verification status
            if (scan) {
              const updated = scan.findings.map((f) =>
                f.id === res.finding_id ? { ...f, verification_status: res.status } : f
              );
              setScan({ ...scan, findings: updated });
            }
          }}
        />
      )}
    </div>
  );
}

