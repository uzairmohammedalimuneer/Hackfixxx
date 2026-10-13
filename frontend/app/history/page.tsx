"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { History, Scan, Trash2, ArrowRight, ExternalLink, ShieldAlert, Loader2 } from "lucide-react";
import { getScanHistory, deleteScan } from "@/lib/api";
import { ScanListItem } from "@/lib/types";
import { SeverityBadge } from "@/components/SeverityBadge";

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchHistory = () => {
    getScanHistory()
      .then(setScans)
      .catch(() => setScans([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleDelete = async (id: string) => {
    if (confirm("Are you sure you want to delete this scan and all its stored findings?")) {
      try {
        await deleteScan(id);
        setScans((prev) => prev.filter((s) => s.id !== id));
      } catch (err: any) {
        alert(`Failed to delete scan: ${err.message}`);
      }
    }
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-950/80 border border-sky-800/60 text-sky-400 text-xs font-mono mb-2">
            <History className="w-3.5 h-3.5" />
            PERSISTENT SCAN HISTORY
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight">
            Security Audit Archive
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Historical scans persisted in SQLite. Review past audits and compare security posture over time.
          </p>
        </div>

        <Link
          href="/new-scan"
          className="bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-xs px-4 py-2.5 rounded-xl transition-all shadow-md shadow-sky-500/20"
        >
          New Scan
        </Link>
      </div>

      <div className="bg-cyber-850 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-400 flex items-center justify-center space-x-2">
            <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
            <span>Loading audit history...</span>
          </div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <Scan className="w-8 h-8 text-slate-400 mx-auto" />
            <h3 className="text-sm font-bold text-slate-200">No Audits in Archive</h3>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              Scans you run are saved in persistent SQLite storage and will appear here.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3.5 px-5">Target URL</th>
                  <th className="py-3.5 px-5">Status</th>
                  <th className="py-3.5 px-5">Total Findings</th>
                  <th className="py-3.5 px-5">Severity Distribution</th>
                  <th className="py-3.5 px-5">Created</th>
                  <th className="py-3.5 px-5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 px-5 font-mono text-slate-200 max-w-xs truncate">
                      <Link href={`/scan/${scan.id}`} className="hover:text-sky-400">
                        {scan.target_url}
                      </Link>
                    </td>
                    <td className="py-3.5 px-5">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold ${
                          scan.status === "completed"
                            ? "bg-emerald-950/80 text-emerald-400 border border-emerald-800"
                            : scan.status === "running"
                            ? "bg-sky-950/80 text-sky-400 border border-sky-800 animate-pulse"
                            : "bg-red-950/80 text-red-400 border border-red-800"
                        }`}
                      >
                        {scan.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3.5 px-5 font-bold text-slate-200">
                      {scan.total_findings}
                    </td>
                    <td className="py-3.5 px-5">
                      <div className="flex items-center space-x-1.5">
                        {scan.critical_count > 0 && <SeverityBadge severity="Critical" size="sm" />}
                        {scan.high_count > 0 && <SeverityBadge severity="High" size="sm" />}
                        {scan.medium_count > 0 && <SeverityBadge severity="Medium" size="sm" />}
                        {scan.low_count > 0 && <SeverityBadge severity="Low" size="sm" />}
                        {scan.total_findings === 0 && <span className="text-slate-400 font-mono">None</span>}
                      </div>
                    </td>
                    <td className="py-3.5 px-5 font-mono text-slate-400">
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-5 text-right space-x-3">
                      <Link
                        href={`/scan/${scan.id}`}
                        className="text-sky-400 hover:text-sky-300 font-semibold inline-flex items-center space-x-1"
                      >
                        <span>Inspect</span>
                        <ArrowRight className="w-3 h-3" />
                      </Link>
                      <button
                        onClick={() => handleDelete(scan.id)}
                        className="text-slate-400 hover:text-red-400 transition-colors"
                        title="Delete scan"
                      >
                        <Trash2 className="w-3.5 h-3.5 inline" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

