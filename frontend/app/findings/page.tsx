"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { AlertTriangle, Search, Filter, ArrowRight, ExternalLink, RefreshCw, Sparkles, Loader2 } from "lucide-react";
import { getScanHistory, getScan } from "@/lib/api";
import { Finding } from "@/lib/types";
import { SeverityBadge } from "@/components/SeverityBadge";
import { RetestModal } from "@/components/RetestModal";
import { AiChatDrawer } from "@/components/AiChatDrawer";

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [retestFinding, setRetestFinding] = useState<Finding | null>(null);
  const [chatFinding, setChatFinding] = useState<Finding | null>(null);

  useEffect(() => {
    // Fetch recent scans and aggregate findings
    getScanHistory()
      .then(async (scans) => {
        const allFindings: Finding[] = [];
        // Take top 5 recent scans
        for (const scanItem of scans.slice(0, 5)) {
          try {
            const detail = await getScan(scanItem.id);
            if (detail.findings) {
              allFindings.push(...detail.findings);
            }
          } catch {}
        }
        setFindings(allFindings);
      })
      .catch(() => setFindings([]))
      .finally(() => setLoading(false));
  }, []);

  const filtered = findings.filter((f) => {
    const matchesSev = severityFilter === "ALL" || f.severity.toUpperCase() === severityFilter;
    const matchesSearch =
      !search ||
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.affected_url.toLowerCase().includes(search.toLowerCase()) ||
      f.owasp_category.toLowerCase().includes(search.toLowerCase());
    return matchesSev && matchesSearch;
  });

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-950/80 border border-sky-800/60 text-sky-400 text-xs font-mono mb-2">
            <AlertTriangle className="w-3.5 h-3.5" />
            AGGREGATED FINDINGS DIRECTORY
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight">
            Security Vulnerabilities & Observations
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Aggregated findings from your scans with concrete evidence, OWASP classification, and live retesting.
          </p>
        </div>

        {/* Filter controls */}
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search findings..."
              className="bg-slate-900 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-sky-500"
            />
          </div>
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

      {loading ? (
        <div className="p-16 text-center text-xs text-slate-400 flex items-center justify-center space-x-2">
          <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
          <span>Aggregating findings from scans...</span>
        </div>
      ) : filtered.length === 0 ? (
        <div className="bg-cyber-850 border border-slate-800 rounded-2xl p-12 text-center text-slate-400 space-y-3">
          <AlertTriangle className="w-8 h-8 text-slate-400 mx-auto" />
          <h3 className="text-sm font-bold text-slate-200">No Findings Found</h3>
          <p className="text-xs max-w-sm mx-auto">
            Run a security scan against an authorized target to detect findings.
          </p>
          <Link
            href="/new-scan"
            className="inline-flex items-center space-x-1.5 bg-sky-500 text-slate-950 font-bold text-xs px-4 py-2 rounded-lg"
          >
            <span>Scan Target</span>
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {filtered.map((f) => (
            <div
              key={f.id}
              className="bg-cyber-850 border border-slate-800 rounded-xl p-4.5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:border-slate-700 transition-colors"
            >
              <div className="space-y-1.5 flex-1 min-w-0">
                <div className="flex items-center space-x-2.5">
                  <SeverityBadge severity={f.severity} size="sm" />
                  <h3 className="text-sm font-bold text-slate-100 truncate">
                    {f.title}
                  </h3>
                </div>
                <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
                  <span className="text-sky-400">{f.owasp_category}</span>
                  <span>•</span>
                  <span className="truncate max-w-xs">{f.affected_url}</span>
                  <span>•</span>
                  <span>Status: {f.verification_status}</span>
                </div>
                <p className="text-xs text-slate-300 line-clamp-2 max-w-3xl">
                  {f.description}
                </p>
              </div>

              <div className="flex items-center space-x-2 flex-shrink-0">
                <button
                  onClick={() => setRetestFinding(f)}
                  className="bg-slate-800 hover:bg-slate-700 text-sky-400 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-colors"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Retest</span>
                </button>
                <button
                  onClick={() => setChatFinding(f)}
                  className="bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border border-sky-500/30 px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-colors"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Ask AI</span>
                </button>
                <Link
                  href={`/scan/${f.scan_id}`}
                  className="p-1.5 text-slate-400 hover:text-slate-200"
                  title="View full scan"
                >
                  <ArrowRight className="w-4 h-4" />
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Retest Modal */}
      {retestFinding && (
        <RetestModal
          isOpen={true}
          onClose={() => setRetestFinding(null)}
          finding={retestFinding}
          onRetestComplete={(res) => {
            setFindings((prev) =>
              prev.map((item) =>
                item.id === res.finding_id ? { ...item, verification_status: res.status } : item
              )
            );
          }}
        />
      )}

      {/* AI Assistant Drawer */}
      {chatFinding && (
        <AiChatDrawer
          isOpen={true}
          onClose={() => setChatFinding(null)}
          scanId={chatFinding.scan_id}
          finding={chatFinding}
        />
      )}
    </div>
  );
}

