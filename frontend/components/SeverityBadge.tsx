import React from "react";
import { SeverityLevel } from "@/lib/types";

interface Props {
  severity: SeverityLevel | string;
  size?: "sm" | "md" | "lg";
}

export function SeverityBadge({ severity, size = "md" }: Props) {
  const norm = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();

  const sizeClasses = {
    sm: "px-2 py-0.5 text-xs font-semibold",
    md: "px-2.5 py-1 text-xs font-bold tracking-wide",
    lg: "px-3 py-1.5 text-sm font-bold tracking-wider",
  }[size];

  const colorClasses: Record<string, string> = {
    Critical: "bg-red-950/80 text-red-400 border border-red-700/60 shadow-sm shadow-red-950",
    High: "bg-orange-950/80 text-orange-400 border border-orange-700/60 shadow-sm shadow-orange-950",
    Medium: "bg-amber-950/80 text-amber-300 border border-amber-700/60",
    Low: "bg-emerald-950/80 text-emerald-300 border border-emerald-700/60",
    Informational: "bg-slate-800 text-slate-300 border border-slate-700",
  };

  const style = colorClasses[norm] || colorClasses.Informational;

  return (
    <span className={`inline-flex items-center rounded-full uppercase ${sizeClasses} ${style}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current mr-1.5 opacity-80" />
      {norm}
    </span>
  );
}

