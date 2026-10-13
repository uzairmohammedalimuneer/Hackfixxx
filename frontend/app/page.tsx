"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Scan,
  AlertTriangle,
  History,
  ArrowRight,
  ShieldCheck,
  Activity,
  Plus
} from "lucide-react";
import { getScanHistory } from "@/lib/api";
import { ScanListItem } from "@/lib/types";
import { SeverityBadge } from "@/components/SeverityBadge";

export default function DashboardPage() {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getScanHistory()
      .then(setScans)
      .catch(() => setScans([]))
      .finally(() => setLoading(false));
  }, []);

  // Compute aggregated totals strictly from real stored database records
  const totalScans = scans.length;
  const totalFindings = scans.reduce((acc, s) => acc + (s.total_findings || 0), 0);
  const criticalCount = scans.reduce((acc, s) => acc + (s.critical_count || 0), 0);
  const highCount = scans.reduce((acc, s) => acc + (s.high_count || 0), 0);
  const mediumCount = scans.reduce((acc, s) => acc + (s.medium_count || 0), 0);
  const lowCount = scans.reduce((acc, s) => acc + (s.low_count || 0), 0);
  const infoCount = scans.reduce((acc, s) => acc + (s.info_count || 0), 0);

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Welcome Banner */}
      <div className="bg-gradient-to-r from-cyber-850 via-cyber-800 to-cyber-850 border border-slate-800 rounded-2xl p-8 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-sky-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 max-w-2xl space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-950/80 border border-sky-800/60 text-sky-400 text-xs font-mono">
            <Activity className="w-3.5 h-3.5 animate-pulse" />
            EVIDENCE-BASED WEBSITE SECURITY SCANNER
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight">
            Security Intelligence for Web Applications
          </h1>
          <p className="text-sm text-slate-400 leading-relaxed">
            Audit authorized web endpoints using genuine non-destructive security checks,
            receive beginner-friendly Gemini AI explanations, and verify manual fixes with live retesting.
          </p>
          <div className="pt-2 flex items-center space-x-3">
            <Link
              href="/new-scan"
              className="inline-flex items-center space-x-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-sm px-5 py-2.5 rounded-xl transition-all shadow-lg shadow-sky-500/20"
            >
              <Plus className="w-4 h-4" />
              <span>Launch New Scan</span>
            </Link>
            <Link
              href="/history"
              className="inline-flex items-center space-x-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm px-4 py-2.5 rounded-xl transition-all border border-slate-700"
            >
              <History className="w-4 h-4" />
              <span>View Scan History</span>
            </Link>
          </div>
        </div>
      </div>

      {/* Aggregate Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        <div className="bg-cyber-850 border border-slate-800 p-4 rounded-xl">
          <span className="text-[11px] font-mono text-slate-400 block">TOTAL SCANS</span>
          <div className="text-2xl font-black text-white mt-1">{totalScans}</div>
          <span className="text-[10px] text-slate-400">Stored in SQLite</span>
        </div>

        <div className="bg-cyber-850 border border-slate-800 p-4 rounded-xl">
          <span className="text-[11px] font-mono text-slate-400 block">TOTAL FINDINGS</span>
          <div className="text-2xl font-black text-sky-400 mt-1">{totalFindings}</div>
          <span className="text-[10px] text-slate-400">Across all audits</span>
        </div>

        <div className="bg-cyber-850 border border-red-950/60 p-4 rounded-xl">
          <span className="text-[11px] font-mono text-red-400 block">CRITICAL</span>
          <div className="text-2xl font-black text-red-400 mt-1">{criticalCount}</div>
          <span className="text-[10px] text-red-400/80">Immediate risk</span>
        </div>

        <div className="bg-cyber-850 border border-orange-950/60 p-4 rounded-xl">
          <span className="text-[11px] font-mono text-orange-400 block">HIGH</span>
          <div className="text-2xl font-black text-orange-400 mt-1">{highCount}</div>
          <span className="text-[10px] text-orange-400/80">Severe flaws</span>
        </div>

        <div className="bg-cyber-850 border border-amber-950/60 p-4 rounded-xl">
          <span className="text-[11px] font-mono text-amber-400 block">MEDIUM</span>
          <div className="text-2xl font-black text-amber-400 mt-1">{mediumCount}</div>
          <span className="text-[10px] text-amber-400/80">Missing defenses</span>
        </div>

        <div className="bg-cyber-850 border border-emerald-950/60 p-4 rounded-xl">
          <span className="text-[11px] font-mono text-emerald-400 block">LOW</span>
          <div className="text-2xl font-black text-emerald-400 mt-1">{lowCount}</div>
          <span className="text-[10px] text-emerald-400/80">Hardening advice</span>
        </div>

        <div className="bg-cyber-850 border border-slate-800 p-4 rounded-xl">
          <span className="text-[11px] font-mono text-slate-400 block">INFO</span>
          <div className="text-2xl font-black text-slate-300 mt-1">{infoCount}</div>
          <span className="text-[10px] text-slate-400">Surface disclosure</span>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="bg-cyber-850 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <History className="w-4 h-4 text-sky-400" />
            <h2 className="text-base font-bold text-slate-100">Recent Security Scans</h2>
          </div>
          <Link
            href="/new-scan"
            className="text-xs font-semibold text-sky-400 hover:text-sky-300 flex items-center space-x-1"
          >
            <span>Scan Target</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {loading ? (
          <div className="p-12 text-center text-xs text-slate-400">
            Loading recent scan records...
          </div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center space-y-4">
            <div className="w-12 h-12 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto text-slate-400">
              <Scan className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-200">No Scans Performed Yet</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto mt-1">
                Enter an authorized website URL or scan our local vulnerable test server to begin detecting security findings.
              </p>
            </div>
            <Link
              href="/new-scan"
              className="inline-flex items-center space-x-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-xs px-4 py-2 rounded-lg transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Start Your First Scan</span>
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-5">Target URL</th>
                  <th className="py-3 px-5">Status</th>
                  <th className="py-3 px-5">Stage</th>
                  <th className="py-3 px-5">Findings</th>
                  <th className="py-3 px-5">Severity Breakdown</th>
                  <th className="py-3 px-5">Created</th>
                  <th className="py-3 px-5 text-right">Actions</th>
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
                    <td className="py-3.5 px-5 font-mono text-slate-400">
                      {scan.stage}
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
                    <td className="py-3.5 px-5 text-slate-400 font-mono">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 px-5 text-right">
                      <Link
                        href={`/scan/${scan.id}`}
                        className="text-sky-400 hover:text-sky-300 font-semibold inline-flex items-center space-x-1"
                      >
                        <span>Inspect</span>
                        <ArrowRight className="w-3 h-3" />
                      </Link>
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

