import React from "react";
import { OwaspCategoryCoverage } from "@/lib/types";
import { ShieldAlert, CheckCircle2, AlertCircle, HelpCircle } from "lucide-react";

interface Props {
  coverage: Record<string, OwaspCategoryCoverage>;
}

export function OwaspCoverageTable({ coverage }: Props) {
  const getStatusBadge = (status: string, count: number) => {
    switch (status) {
      case "findings_present":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-950/80 text-red-400 border border-red-800">
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
            {count} {count === 1 ? "Finding" : "Findings"} Present
          </span>
        );
      case "no_findings_detected":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            No Findings Detected
          </span>
        );
      case "assessment_limited":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/80 text-amber-400 border border-amber-800">
            <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
            Assessment Limited
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
            Not Assessed
          </span>
        );
    }
  };

  const categories = Object.values(coverage);

  return (
    <div className="bg-cyber-850 border border-slate-800 rounded-xl overflow-hidden">
      <div className="p-4 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
            OWASP Top 10:2025 Coverage Mapping
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Honest assessment scope. Passive URL scanning assesses observable headers, transport, and surface configuration.
          </p>
        </div>
        <div className="text-[11px] font-mono px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-400">
          Official 2025 Taxonomy
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/80 text-slate-400 font-mono text-[11px] border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">Code</th>
              <th className="py-3 px-4">Category Name</th>
              <th className="py-3 px-4">Coverage Status</th>
              <th className="py-3 px-4">Passive Audit Scope & Limitations</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {categories.map((cat) => (
              <tr key={cat.category_id} className="hover:bg-slate-800/30 transition-colors">
                <td className="py-3 px-4 font-mono font-bold text-sky-400">
                  {cat.category_id}
                </td>
                <td className="py-3 px-4 font-semibold text-slate-200">
                  {cat.category_name}
                </td>
                <td className="py-3 px-4">
                  {getStatusBadge(cat.status, cat.finding_count)}
                </td>
                <td className="py-3 px-4 text-slate-400 max-w-md">
                  {cat.limitation_note}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="p-3 bg-slate-900/40 border-t border-slate-800 text-[11px] text-slate-400 italic">
        * "No findings detected" means only that configured passive checks did not detect an issue; it does not claim the target website is completely secure.
      </div>
    </div>
  );
}

