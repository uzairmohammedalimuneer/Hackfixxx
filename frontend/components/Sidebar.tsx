"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert,
  LayoutDashboard,
  Scan,
  History,
  FileText,
  Settings,
  AlertTriangle,
  Sparkles,
  ExternalLink,
  CheckCircle2,
  Lock
} from "lucide-react";
import { getHealth } from "@/lib/api";
import { SystemHealth } from "@/lib/types";

export function Sidebar() {
  const pathname = usePathname();
  const [health, setHealth] = useState<SystemHealth | null>(null);

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  const navItems = [
    { label: "Dashboard", href: "/", icon: LayoutDashboard },
    { label: "New Scan", href: "/new-scan", icon: Scan },
    { label: "Scan History", href: "/history", icon: History },
    { label: "Findings", href: "/findings", icon: AlertTriangle },
    { label: "Reports", href: "/reports", icon: FileText },
    { label: "Settings", href: "/settings", icon: Settings },
  ];

  return (
    <aside className="w-64 bg-cyber-900 border-r border-slate-800 flex flex-col justify-between h-screen sticky top-0">
      <div>
        {/* Logo and Brand Header */}
        <div className="p-6 border-b border-slate-800/80">
          <Link href="/" className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-sky-500/10 border border-sky-400/30 flex items-center justify-center text-sky-400 shadow-lg shadow-sky-500/10">
              <ShieldAlert className="w-5 h-5 text-sky-400" />
            </div>
            <div>
              <span className="font-extrabold tracking-wider text-slate-100 text-lg flex items-center gap-1.5">
                HACKFIX <span className="text-sky-400 text-sm font-semibold px-1.5 py-0.5 rounded bg-sky-950/80 border border-sky-800/60">AI</span>
              </span>
              <p className="text-[10px] text-slate-400 uppercase tracking-widest font-mono">
                Website Security Engine
              </p>
            </div>
          </Link>
        </div>

        {/* Navigation Links */}
        <nav className="p-4 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center space-x-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? "bg-sky-500/10 text-sky-400 border border-sky-500/30 shadow-sm"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? "text-sky-400" : "text-slate-400"}`} />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* System Status and Engine Indicators */}
      <div className="p-4 border-t border-slate-800 bg-cyber-850/60 text-xs text-slate-400 space-y-2.5">
        <div className="flex items-center justify-between text-[11px] font-mono">
          <span className="text-slate-400">ENGINE STATUS</span>
          <span className="flex items-center text-emerald-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse" />
            Online
          </span>
        </div>

        <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-slate-400 flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-sky-400" /> Gemini AI:
            </span>
            <span className={`font-semibold ${health?.capabilities?.gemini_ai?.configured ? "text-emerald-400" : "text-amber-400"}`}>
              {health?.capabilities?.gemini_ai?.configured ? "Active" : "Fallback"}
            </span>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-slate-400 flex items-center gap-1">
              <Lock className="w-3 h-3 text-sky-400" /> SSRF Shield:
            </span>
            <span className="text-emerald-400 font-semibold">Active</span>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-slate-400 flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-slate-400" /> ZAP Baseline:
            </span>
            <span className="text-slate-400">
              {health?.capabilities?.owasp_zap?.enabled ? "Enabled" : "Disabled (Safe)"}
            </span>
          </div>
        </div>

        <div className="text-[10px] text-slate-400 text-center pt-1 font-mono">
          v1.0.0 • Non-Destructive Auditor
        </div>
      </div>
    </aside>
  );
}

