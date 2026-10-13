"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { FileText, FileDown, Eye, History, ArrowRight, Loader2, ShieldCheck } from "lucide-react";
import { getScanHistory, getPdfReportUrl, getHtmlReportUrl } from "@/lib/api";
import { ScanListItem } from "@/lib/types";

export default function ReportsPage() {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getScanHistory()
      .then((data) => setScans(data.filter((s) => s.status === "completed")))
      .catch(() => setScans([]))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-950/80 border border-sky-800/60 text-sky-400 text-xs font-mono mb-2">
          <FileText className="w-3.5 h-3.5" />
          SECURITY AUDIT REPORTS
        </div>
        <h1 className="text-2xl font-black text-white tracking-tight">
          Downloadable Security Assessment Reports
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Export verified executive and technical reports in PDF, HTML, or JSON formats with real evidence and OWASP Top 10 mapping.
        </p>
      </div>

      <div className="bg-cyber-850 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        {loading ? (
          <div className="p-16 text-center text-xs text-slate-400 flex items-center justify-center space-x-2">
            <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
            <span>Loading completed audit reports...</span>
          </div>
        ) : scans.length === 0 ? (
          <div className="p-16 text-center space-y-3">
            <FileText className="w-8 h-8 text-slate-400 mx-auto" />
            <h3 className="text-sm font-bold text-slate-200">No Reports Available</h3>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              Complete a security scan to automatically generate downloadable PDF and HTML audit reports.
            </p>
            <Link
              href="/new-scan"
              className="inline-flex items-center space-x-1.5 bg-sky-500 text-slate-950 font-bold text-xs px-4 py-2 rounded-lg"
            >
              <span>Scan Target</span>
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3.5 px-5">Target Website</th>
                  <th className="py-3.5 px-5">Findings Count</th>
                  <th className="py-3.5 px-5">Completed At</th>
                  <th className="py-3.5 px-5 text-right">Download Formats</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 px-5 font-mono text-slate-200">
                      <Link href={`/scan/${scan.id}`} className="hover:text-sky-400">
                        {scan.target_url}
                      </Link>
                    </td>
                    <td className="py-3.5 px-5 font-bold text-slate-200">
                      {scan.total_findings}
                    </td>
                    <td className="py-3.5 px-5 text-slate-400 font-mono">
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-5 text-right space-x-2">
                      <a
                        href={getHtmlReportUrl(scan.id)}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center space-x-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 px-3 py-1.5 rounded-lg font-semibold transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>Preview HTML</span>
                      </a>
                      <a
                        href={getPdfReportUrl(scan.id)}
                        download
                        className="inline-flex items-center space-x-1.5 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold px-3 py-1.5 rounded-lg transition-colors shadow-sm shadow-sky-500/20"
                      >
                        <FileDown className="w-3.5 h-3.5" />
                        <span>PDF Report</span>
                      </a>
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

