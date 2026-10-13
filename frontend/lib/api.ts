import {
  ScanDetail,
  ScanListItem,
  RetestResult,
  SystemHealth
} from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000/api";

export async function getHealth(): Promise<SystemHealth> {
  const res = await fetch(`${API_BASE}/health`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Health check failed: ${res.statusText}`);
  }
  return res.json();
}

export async function createScan(
  targetUrl: string,
  authorizationAcknowledged: boolean,
  maxPages: number = 15,
  crawlDepth: number = 2
): Promise<{ id: string; target_url: string; status: string; stage: string }> {
  const res = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target_url: targetUrl,
      authorization_acknowledged: authorizationAcknowledged,
      max_pages: maxPages,
      crawl_depth: crawlDepth,
    }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || "Failed to start scan");
  }

  return res.json();
}

export async function getScan(scanId: string): Promise<ScanDetail> {
  const res = await fetch(`${API_BASE}/scan/${scanId}`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Failed to fetch scan details: ${res.statusText}`);
  }
  return res.json();
}

export async function getScanHistory(): Promise<ScanListItem[]> {
  const res = await fetch(`${API_BASE}/history`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Failed to fetch scan history: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteScan(scanId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/scan/${scanId}`, { method: "DELETE" });
  if (!res.ok) {
    throw new Error(`Failed to delete scan: ${res.statusText}`);
  }
}

export async function sendChatMessage(
  scanId: string,
  question: string,
  findingId?: string
): Promise<{
  answer: string;
  source: "gemini" | "deterministic_fallback";
  model_used?: string | null;
  suggested_questions: string[];
  finding_id?: string;
}> {
  const res = await fetch(`${API_BASE}/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      scan_id: scanId,
      finding_id: findingId,
      question: question,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Chat request failed");
  }

  return res.json();
}

export async function retestFinding(findingId: string): Promise<RetestResult> {
  const res = await fetch(`${API_BASE}/retest`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ finding_id: findingId }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Retest failed");
  }

  return res.json();
}

export function getPdfReportUrl(scanId: string): string {
  return `${API_BASE}/report/${scanId}/pdf`;
}

export function getHtmlReportUrl(scanId: string): string {
  return `${API_BASE}/report/${scanId}/html`;
}

