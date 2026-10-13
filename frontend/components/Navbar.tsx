"use client";

import React from "react";
import Link from "next/link";
import { Plus, ShieldCheck, Terminal } from "lucide-react";

export function Navbar() {
  return (
    <header className="h-16 border-b border-slate-800 bg-cyber-900/80 backdrop-blur px-8 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center space-x-3 text-sm text-slate-400">
        <span className="flex items-center gap-1.5 text-xs font-mono px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700 text-slate-300">
          <ShieldCheck className="w-3.5 h-3.5 text-sky-400" />
          TARGET SCOPE: HTTP/HTTPS ONLY
        </span>
        <span className="text-slate-600">|</span>
        <span className="text-xs text-slate-400 hidden sm:inline">
          Workflow: Scan &rarr; Find &rarr; Prove &rarr; Explain &rarr; Fix &rarr; Retest
        </span>
      </div>

      <div className="flex items-center space-x-4">
        <Link
          href="/new-scan"
          className="inline-flex items-center space-x-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs px-3.5 py-2 rounded-lg transition-colors shadow-md shadow-sky-500/20"
        >
          <Plus className="w-4 h-4" />
          <span>New Scan</span>
        </Link>
      </div>
    </header>
  );
}

