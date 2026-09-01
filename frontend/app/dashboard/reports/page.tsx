"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { FileText, Download, Loader2, AlertTriangle, CheckCircle2 } from "lucide-react";

interface Project { id: string; name: string; }

export default function ReportsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<string>("");
  const [findings, setFindings] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [engagements, setEngagements] = useState<any[]>([]);
  const [exportHistory, setExportHistory] = useState<{id: string, engagement: string, format: string, date: string, type: string}[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [engagementId, setEngagementId] = useState<string>("");

  useEffect(() => {
    async function loadProjects() {
      try {
        const res = await api.get("/api/v1/projects/").catch(() => ({ data: { data: [] } }));
        const data = res.data?.data ?? res.data ?? [];
        const list = Array.isArray(data) ? data : [];
        setProjects(list);
        if (list.length > 0) setSelectedProject(list[0].id);
      } catch (e: any) {
        setError(e?.response?.data?.detail || "Failed to load projects");
      } finally {
        setLoading(false);
      }
    }
    loadProjects();
  }, []);

  useEffect(() => {
    if (!selectedProject) return;
    async function loadReportData() {
      setError(null);
      try {
        const [summaryRes, findingsRes, engRes] = await Promise.all([
          api.get(`/api/v1/reports/${selectedProject}/summary`).catch(() => null),
          api.get(`/api/v1/reports/${selectedProject}/findings`).catch(() => null),
          api.get("/api/v1/engagements/").catch(() => ({ data: { data: [] } })),
        ]);
        if (summaryRes?.data) setSummary(summaryRes.data?.data ?? summaryRes.data);
        if (findingsRes?.data) {
          const f = findingsRes.data?.data?.findings ?? findingsRes.data?.findings ?? [];
          setFindings(Array.isArray(f) ? f : []);
        }
        const engs = engRes.data?.data ?? engRes.data ?? [];
        const arr = Array.isArray(engs) ? engs : [];
        const filtered = arr.filter((e: any) => e.project_id === selectedProject);
        setEngagements(filtered);
        if (filtered.length > 0) setEngagementId(filtered[0].id);
        else if (arr.length > 0) setEngagementId(arr[0].id);
        // Try to load export history from audit logs if workspace available
        try {
          const wsRes = await api.get("/api/v1/workspaces").catch(() => null);
          const wsData = wsRes?.data?.data ?? wsRes?.data ?? [];
          const wsList = Array.isArray(wsData) ? wsData : [];
          if (wsList.length > 0) {
            const auditRes = await api.get(`/api/v1/workspaces/${wsList[0].id}/audit-logs/recent`, { params: { limit: 20 } }).catch(() => null);
            const logs = auditRes?.data?.data ?? auditRes?.data ?? [];
            if (Array.isArray(logs)) {
              const exps = logs.filter((l: any) => l.action?.includes("export") || l.action?.includes("report")).map((l: any) => ({
                id: l.id, engagement: l.project_id?.slice(0,8) || selectedProject.slice(0,8), format: l.details?.format || "pdf", date: l.created_at, type: l.action
              }));
              if (exps.length > 0) setExportHistory(exps);
            }
          }
        } catch {}
      } catch (e: any) {
        setError(e?.response?.data?.detail || "Failed to load report data");
      }
    }
    loadReportData();
  }, [selectedProject]);

  async function download(format: "json" | "csv" | "html" | "pdf", overrideEngId?: string) {
    if (!selectedProject) return;
    const effEngId = overrideEngId || engagementId;
    const key = format === "pdf" ? `pdf-${effEngId}` : format;
    setDownloading(key);
    try {
      if (format === "pdf") {
        if (!effEngId) throw new Error("No engagement found for this project — create one first");
        const pdfTargets = findings.length && findings[0]?.host && findings[0].host !== "-" && findings[0].host !== "—" && findings[0].host.trim() !== "" ? [findings[0].host] : ["testphp.vulnweb.com"];
        const res = await api.post(
          `/api/v1/projects/${selectedProject}/pentest/report?format=pdf`,
          { engagement_id: effEngId, targets: pdfTargets, format: "pdf" },
          { responseType: "blob" }
        );
        const blob = new Blob([res.data], { type: "application/pdf" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = `report-${selectedProject.slice(0,8)}.pdf`; a.click();
        URL.revokeObjectURL(url);
        setExportHistory(prev => [{id: Date.now().toString(), engagement: effEngId.slice(0,8), format: "pdf", date: new Date().toISOString(), type: "pentest/report"}, ...prev].slice(0,10));
      } else {
        const res = await api.get(`/api/v1/reports/${selectedProject}/export`, {
          params: { format, min_severity: "info" },
          responseType: format === "json" ? "json" : "blob",
        });
        let blob: Blob;
        if (format === "json") {
          blob = new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
        } else {
          blob = new Blob([res.data], { type: format === "csv" ? "text/csv" : "text/html" });
        }
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = `report-${selectedProject.slice(0,8)}.${format}`; a.click();
        URL.revokeObjectURL(url);
        setExportHistory(prev => [{id: Date.now().toString(), engagement: selectedProject.slice(0,8), format, date: new Date().toISOString(), type: `reports/export`}, ...prev].slice(0,10));
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message || `Download ${format} failed`);
    } finally {
      setDownloading(null);
    }
  }

  async function downloadBounty(engId: string, platform: "hackerone" | "bugcrowd") {
    setDownloading(`bounty-${engId}-${platform}`);
    try {
      const res = await api.post(`/api/v1/projects/${selectedProject}/engagements/${engId}/export-bounty`, { platform });
      const md = res.data?.data?.markdown || JSON.stringify(res.data, null, 2);
      const blob = new Blob([md], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `bounty-${engId.slice(0,8)}-${platform}.md`; a.click();
      URL.revokeObjectURL(url);
      setExportHistory(prev => [{id: Date.now().toString(), engagement: engId.slice(0,8), format: "md", date: new Date().toISOString(), type: `export-bounty:${platform}`}, ...prev].slice(0,10));
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Bounty export failed");
    } finally {
      setDownloading(null);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--primary)]" />
        <span className="ml-2 text-sm text-[var(--muted-foreground)]">Loading reports...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold flex items-center gap-2"><FileText className="h-5 w-5 text-[var(--primary)]" /> Reports</h1>
        <p className="text-sm text-[var(--muted-foreground)]">تقارير حقيقية من <code className="bg-[var(--muted)] px-1 rounded">GET /api/v1/reports/{`{id}`}/summary</code> و <code className="bg-[var(--muted)] px-1 rounded">/export</code> — تحميل PDF/JSON/CSV/HTML</p>
      </div>

      {error && <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded p-3 flex gap-2"><AlertTriangle className="h-4 w-4 shrink-0" />{error}</div>}

      <div className="flex gap-3 items-center flex-wrap">
        <select className="rounded-md border border-[var(--border)] bg-[var(--background)] px-3 py-2 text-sm" value={selectedProject} onChange={e => setSelectedProject(e.target.value)}>
          <option value="">اختر مشروع...</option>
          {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        {summary && (
          <div className="text-xs text-[var(--muted-foreground)]">
            Findings: {summary.findings_count ?? findings.length} • Critical: {summary.by_severity?.critical ?? 0} • High: {summary.by_severity?.high ?? 0}
          </div>
        )}
      </div>

      {projects.length === 0 ? (
        <Card><CardContent className="p-6 text-sm text-[var(--muted-foreground)]">No projects yet. Create one from Projects → New Project first.</CardContent></Card>
      ) : (
        <>
          <div className="grid gap-3 md:grid-cols-4">
            <Button onClick={() => download("pdf")} disabled={!!downloading} className="bg-[var(--primary)]"><Download className="h-4 w-4 mr-1" /> {downloading === "pdf" ? "جارٍ التحميل..." : "تحميل PDF (pentest)"}</Button>
            <Button onClick={() => download("json")} disabled={!!downloading} variant="outline">{downloading === "json" ? "جارٍ..." : "تحميل JSON"}</Button>
            <Button onClick={() => download("csv")} disabled={!!downloading} variant="outline">{downloading === "csv" ? "جارٍ..." : "تحميل CSV"}</Button>
            <Button onClick={() => download("html")} disabled={!!downloading} variant="outline">{downloading === "html" ? "جارٍ..." : "تحميل HTML"}</Button>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><FileText className="h-4 w-4" /> Findings في التقرير</CardTitle>
              <CardDescription>{findings.length} finding(s) — من <code className="bg-[var(--muted)] px-1 rounded">GET /api/v1/reports/{selectedProject.slice(0,8)}/findings</code></CardDescription>
            </CardHeader>
            <CardContent>
              {findings.length === 0 ? (
                <p className="text-sm text-[var(--muted-foreground)]">No findings yet. ابدأ فحص من Scans → Start Scan ليتولد تقرير ثم ارجع هنا.</p>
              ) : (
                <div className="space-y-2 max-h-[400px] overflow-y-auto">
                  {findings.map((f: any, i: number) => (
                    <div key={f.id || i} className="flex items-center gap-3 p-3 rounded border border-[var(--border)] bg-[var(--card)]/50 text-sm">
                      <span className={`text-xs px-2 py-1 rounded ${f.severity === "CRITICAL" ? "bg-red-900 text-red-100" : f.severity === "HIGH" ? "bg-red-600 text-white" : "bg-amber-600 text-white"}`}>{f.severity || "MEDIUM"}</span>
                      <span className="font-mono text-xs truncate">{f.template_id || f.title || f.id}</span>
                      <span className="text-xs text-[var(--muted-foreground)] truncate">{f.host || f.location || ""}</span>
                      <span className="ml-auto text-xs text-[var(--muted-foreground)]">CVSS {f.cvss_score ?? "-"}</span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>تقارير لكل Engagement — تحميل PDF/Markdown</CardTitle><CardDescription>كل صف ينادي <code className="bg-[var(--muted)] px-1 rounded">POST /api/v1/projects/{`{id}`}/pentest/report</code> و <code className="bg-[var(--muted)] px-1 rounded">POST /api/v1/projects/{`{id}`}/engagements/{`{eid}`}/export-bounty</code> حقيقي</CardDescription></CardHeader>
            <CardContent>
              {engagements.length === 0 ? (
                <p className="text-sm text-[var(--muted-foreground)]">لا يوجد Engagements لهذا المشروع — أنشئ واحدًا من Projects.</p>
              ) : (
                <div className="space-y-2">
                  {engagements.map((eng: any) => (
                    <div key={eng.id} className="flex items-center gap-2 p-3 rounded border border-[var(--border)] bg-[var(--card)]/50 flex-wrap">
                      <span className="font-medium text-sm">{eng.name}</span>
                      <span className="text-xs font-mono text-[var(--muted-foreground)]">{eng.id.slice(0,8)}</span>
                      <span className="text-xs px-1.5 py-0.5 rounded bg-[var(--muted)] border border-[var(--border)]">{eng.status}</span>
                      <div className="ml-auto flex gap-2">
                        <Button size="sm" variant="outline" onClick={() => download("pdf", eng.id)} disabled={downloading?.startsWith("pdf")} className="h-7 text-xs">
                          <Download className="h-3 w-3 mr-1" /> PDF
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => downloadBounty(eng.id, "hackerone")} disabled={downloading === `bounty-${eng.id}-hackerone`} className="h-7 text-xs">
                          {downloading === `bounty-${eng.id}-hackerone` ? <Loader2 className="h-3 w-3 animate-spin" /> : "HackerOne MD"}
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => downloadBounty(eng.id, "bugcrowd")} disabled={downloading === `bounty-${eng.id}-bugcrowd`} className="h-7 text-xs">
                          {downloading === `bounty-${eng.id}-bugcrowd` ? <Loader2 className="h-3 w-3 animate-spin" /> : "Bugcrowd MD"}
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {exportHistory.length > 0 && (
            <Card>
              <CardHeader><CardTitle className="text-sm">سجل التصدير الأخير</CardTitle><CardDescription>{exportHistory.length} تصدير — من الـ API أو المحلي</CardDescription></CardHeader>
              <CardContent>
                <div className="space-y-1 text-xs font-mono">
                  {exportHistory.map(h => (
                    <div key={h.id} className="flex gap-2 p-2 rounded border border-[var(--border)] bg-[var(--muted)]/20">
                      <span className="px-1.5 py-0.5 rounded bg-[var(--primary)]/20 text-[var(--primary)] border border-[var(--primary)]/20">{h.format.toUpperCase()}</span>
                      <span>{h.type}</span>
                      <span className="text-[var(--muted-foreground)]">eng {h.engagement}</span>
                      <span className="ml-auto text-[var(--muted-foreground)]">{new Date(h.date).toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader><CardTitle className="text-sm">API Endpoints المستخدمة فعليًا</CardTitle></CardHeader>
            <CardContent className="text-xs text-[var(--muted-foreground)] space-y-1 font-mono">
              <div>GET /api/v1/reports/{`{project_id}`}/summary</div>
              <div>GET /api/v1/reports/{`{project_id}`}/findings</div>
              <div>GET /api/v1/reports/{`{project_id}`}/export?format=json|csv|html</div>
              <div>POST /api/v1/projects/{`{project_id}`}/pentest/report?format=pdf</div>
              <div>POST /api/v1/projects/{`{project_id}`}/engagements/{`{eid}`}/export-bounty {"{platform}"}</div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
