export type SeverityLevel = "Critical" | "High" | "Medium" | "Low" | "Informational";
export type ConfidenceLevel = "Confirmed" | "High" | "Medium" | "Low";
export type EvidenceStatus = "confirmed_observation" | "suspected_vulnerability" | "manual_review_required";
export type VerificationStatus = "unverified" | "verified_fixed" | "still_present" | "inconclusive" | "not_supported";
export type ScanStage = "QUEUED" | "FIND" | "PROVE" | "FIX" | "VERIFY" | "COMPLETED" | "FAILED";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type CoverageStatus = "findings_present" | "no_findings_detected" | "assessment_limited" | "not_assessed";

export interface OwaspCategoryCoverage {
  category_id: string;
  category_name: string;
  status: CoverageStatus;
  finding_count: number;
  limitation_note: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  owasp_category: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  evidence_status: EvidenceStatus;
  description: string;
  impact: string;
  affected_url: string;
  evidence: Record<string, any>;
  recommended_fix: string;
  example_before?: string | null;
  example_after?: string | null;
  limitations: string;
  verification_status: VerificationStatus;
  source: string;
  references: string[];
  first_seen: string;
  last_seen: string;
  beginner_explanation?: string;
  why_it_matters?: string;
}

export interface ScanLog {
  id: number;
  timestamp: string;
  stage: string;
  level: "INFO" | "WARNING" | "ERROR";
  message: string;
}

export interface ScanSummary {
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  pages_scanned: number;
  duration_seconds: number;
  owasp_coverage: Record<string, OwaspCategoryCoverage>;
}

export interface ScanDetail {
  id: string;
  target_url: string;
  authorization_acknowledged: boolean;
  status: ScanStatus;
  stage: ScanStage;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  error_message?: string | null;
  summary: ScanSummary;
  findings: Finding[];
  logs: ScanLog[];
}

export interface ScanListItem {
  id: string;
  target_url: string;
  status: ScanStatus;
  stage: ScanStage;
  created_at: string;
  completed_at?: string | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
}

export interface RetestResult {
  id: string;
  scan_id: string;
  finding_id: string;
  status: VerificationStatus;
  timestamp: string;
  previous_evidence: Record<string, any>;
  new_evidence: Record<string, any>;
  details: string;
}

export interface ChatMessage {
  sender: "user" | "assistant";
  text: string;
  source?: "gemini" | "deterministic_fallback";
  model_used?: string | null;
  suggested_questions?: string[];
  timestamp: string;
}

export interface SystemHealth {
  status: string;
  app_name: string;
  version: string;
  capabilities: {
    scanner_engine: string;
    gemini_ai: {
      enabled: boolean;
      configured: boolean;
      model: string;
      fallback_available: boolean;
    };
    owasp_zap: {
      enabled: boolean;
      available: boolean;
      message: string;
    };
    retesting: string;
    pdf_reports: string;
    ssrf_protection: string;
  };
}

