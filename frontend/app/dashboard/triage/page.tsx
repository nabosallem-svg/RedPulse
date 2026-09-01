"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Flag, Loader2, AlertTriangle, CheckCircle2, Clock, FileText, ChevronDown } from "lucide-react";

interface TriageItem {
  id: string;
  finding_id: string;
  project_id: string;
  decision: string;
  reason?: string;
  evidence?: string;
  ai_prediction?: string;
  ai_was_correct?: boolean;
  created_at?: string;
  analyst_id?: string;
}

interface TriageFilter {
  decision: "false_positive" | "true_positive" | "under_review";
  project_id?: string;
}

export default function TriagePage() {
  const [items, setItems] = useState<TriageItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<TriageFilter>({ decision: "false_positive" });

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const params: any = { limit: 50 };
        if (filter.project_id) params.project_id = filter.project_id;
        // Real endpoint: GET /api/v1/triage/feedback — returns TriageFeedback list
        const res = await api.get("/api/v1/triage/feedback", { params });
        const data = res.data?.data ?? res.data ?? [];
        const list: TriageItem[] = Array.isArray(data) ? data : [];
        // Also try to enrich with history for reason/evidence if missing
        const decisionFilter = filter.decision === "false_positive" ? false_positive : filter.decision;
        const filtered = list.filter(item => item.decision === decisionFilter);
        // For filtered items, try to fetch history to get reason/evidence if not present
        const enriched = await Promise.all(filtered.map(async (it) => {
          if (it.reason) return it;
          try {
            const hRes = await api.get(`/api/v1/findings/${it.finding_id}/triage/history`);
            const hist = hRes.data?.data ?? hRes.data ?? [];
            const arr = Array.isArray(hist) ? hist : [];
            const match = arr.find((h: any) => h.id === it.id) || arr[0];
            if (match) {
              return { ...it, reason: match.reason || it.reason, evidence: match.evidence || it.evidence, created_at: match.created_at || it.created_at };
            }
          } catch {}
          return it;
        }));
        setItems(enriched);
      } catch (e: any) {
        const status = e?.response?.status;
        if (status === 404) {
          setItems([]);
        } else {
          setError(e?.response?.data?.detail || "Failed to load triage feedback");
        }
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [filter]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--primary)]" />
        <span className="ml-2 text-sm text-[var(--muted-foreground)]">Loading triage...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2"><Flag className="h-6 w-6 text-[var(--primary)]" /> Triage — False Positives</h1>
        <p className="text-sm text-[var(--muted-foreground)]">قائمة الـ Findings المعلّمة — من <code className="bg-[var(--muted)] px-1 rounded">GET /api/v1/triage/feedback</code> و <code className="bg-[var(--muted)] px-1 rounded">POST /api/v1/findings/{`{id}`}/false-positive</code></p>
      </div>

      <div className="flex gap-3 mb-4">
        <select
          className="rounded border border-[var(--border)] bg-[var(--card)] p-2 text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-[var(--primary)]"
          onChange={(e) => {
            const val = e.target.value;
            if (val === "all") {
              setFilter({ decision: "false_positive" });
            } else if (val === "tp") {
              setFilter({ decision: "true_positive" });
            } else if (val === "ur") {
              setFilter({ decision: "under_review" });
            } else {
              setFilter({ decision: val as any, project_id: undefined });
            }
          }}
          value={filter.decision}
        >
          <option value="all">全部决策</option>
          <option value="false_positive">False Positive</option>
          <option value="true_positive">True Positive</option>
          <option value="under_review">Under Review</option>
        </select>

        <select
          className="rounded border border-[var(--border)] bg-[var(--card)] p-2 text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-[var(--primary)]"
          onChange={(e) => setFilter({ ...filter, project_id: e.target.value || undefined })}
          disabled={filter.decision !== "false_positive"}
        >
          <option value="">All Projects</option>
          {/* Project options would be populated dynamically */}
          <option value="proj_1">Project 1</option>
          <option value="proj_2">Project 2</option>
        </select>
      </div>

      {error && <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded p-3 flex gap-2"><AlertTriangle className="h-4 w-4 shrink-0" />{error}</div>}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Flag className="h-5 w-5 text-amber-400" /> False Positive Findings</CardTitle>
          <CardDescription>{items.length} marked as false_positive — سبب ودليل وتاريخ كل واحد</CardDescription>
        </CardHeader>
        <CardContent>
          {items.length === 0 ? (
            <div className="text-center py-8 space-y-2">
              <Flag className="h-8 w-8 mx-auto text-[var(--muted-foreground)] opacity-50" />
              <p className="text-sm text-[var(--muted-foreground)]">لا يوجد False Positives بعد.</p>
              <p className="text-xs text-[var(--muted-foreground)]">علّم أي Finding كـ False Positive من صفحة Findings عبر <code className="bg-[var(--muted)] px-1 rounded">POST /api/v1/findings/{`{id}`}/false-positive</code> وسيظهر هنا.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {items.map((it) => (
                <div key={it.id} className="rounded border border-amber-500/20 bg-amber-500/5 p-4 space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs px-2 py-1 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">FALSE POSITIVE</span>
                      <span className="font-mono text-xs text-[var(--muted-foreground)]">{it.finding_id.slice(0,8)}...</span>
                    </div>
                    <span className="text-xs text-[var(--muted-foreground)] flex items-center gap-1"><Clock className="h-3 w-3" />{it.created_at ? new Date(it.created_at).toLocaleString() : "—"}</span>
                  </div>
                  <div className="grid gap-2 md:grid-cols-2 text-sm">
                    <div>
                      <div className="text-xs font-medium text-[var(--muted-foreground)]">السبب (reason):</div>
                      <div className="mt-1 rounded bg-black/30 p-2 text-xs border border-[var(--border)]">{it.reason || "— لا يوجد سبب مسجل —"}</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-[var(--muted-foreground)]">الدليل (evidence):</div>
                      <div className="mt-1 rounded bg-black/30 p-2 text-xs border border-[var(--border)] break-all">{it.evidence || "—"}</div>
                    </div>
                  </div>
                  <div className="flex gap-2 text-xs text-[var(--muted-foreground)]">
                    <span>Project: <code className="bg-black/30 px-1 rounded">{it.project_id?.slice(0,8) || "—"}</code></span>
                    <span>• AI: {it.ai_prediction || "—"} {it.ai_was_correct !== undefined ? (it.ai_was_correct ? "✓" : "✗") : ""}</span>
                    <span className="ml-auto flex gap-1">
                      <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => window.location.href = `/dashboard/engagements/${it.finding_id}`}>View Finding</Button>
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">API الحقيقي المستخدم</CardTitle></CardHeader>
        <CardContent className="text-xs font-mono text-[var(--muted-foreground)] space-y-1">
          <div>GET /api/v1/triage/feedback?limit=50</div>
          <div>GET /api/v1/findings/{`{id}`}/triage/history</div>
          <div>POST /api/v1/findings/{`{id}`}/false-positive {"{reason, evidence}"}</div>
          <div>POST /api/v1/findings/{`{id}`}/triage {"{decision, reason, evidence}"}</div>
        </CardContent>
      </Card>
    </div>
  );
}
