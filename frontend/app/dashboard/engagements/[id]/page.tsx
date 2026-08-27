"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Shield, Bug, FileText, Download, ExternalLink, CheckCircle, AlertTriangle, ChevronDown, ChevronUp, Loader2 } from "lucide-react";
import { AttackPathGraph } from "@/components/security/attack-path-graph";

type Finding = {
  id?: string;
  fingerprint?: string;
  template_id?: string;
  title?: string;
  severity: string;
  cvss_score?: number;
  cvss_vector?: string;
  host?: string;
  evidence?: string;
  compliance?: { owasp: string; pci: string; iso: string };
  poc?: { request?: string; response?: string; is_passive?: boolean };
  status?: string;
};

export default function FindingsPage() {
  const params = useParams<{ id: string }>();
  const engagementId = params.id as string;
  const [projectId, setProjectId] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [compliance, setCompliance] = useState<any>(null);
  const [attackPaths, setAttackPaths] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [exportMd, setExportMd] = useState<string | null>(null);
  const [exportPlatform, setExportPlatform] = useState<"hackerone" | "bugcrowd">("hackerone");
  const [showExport, setShowExport] = useState(false);
  const [verifying, setVerifying] = useState<string | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: "error" | "success" } | null>(null);

  function showToast(msg: string, type: "error" | "success" = "error") {
    setToast({ msg, type });
    if (type === "success") setTimeout(() => setToast(null), 4000);
  }

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const engRes = await api.get(`/api/v1/engagements/${engagementId}`).catch(() => null);
        let pid: string | null = engRes?.data?.project_id || null;
        if (!pid) {
          const projRes = await api.get("/api/v1/projects/");
          const list = projRes.data?.data ?? projRes.data;
          if (Array.isArray(list) && list.length) pid = list[0].id;
        }
        if (pid) {
          setProjectId(pid);
          try {
            const comp = await api.get(`/api/v1/projects/${pid}/compliance-summary`);
            if (comp.data?.data?.compliance) setCompliance(comp.data.data.compliance);
            const enriched = comp.data?.data?.compliance?.enriched;
            if (Array.isArray(enriched) && enriched.length) {
              setFindings(enriched.map((f: any) => ({
                fingerprint: f.fingerprint || f.template_id,
                template_id: f.template_id,
                severity: f.severity || "MEDIUM",
                cvss_score: f.cvss_score,
                host: f.host,
                evidence: f.evidence,
                title: f.title || f.template_id,
                compliance: f.compliance,
                poc: f.poc,
              })));
            }
          } catch {}
          try {
            const ap = await api.get(`/api/v1/projects/${pid}/engagements/${engagementId}/attack-paths`);
            setAttackPaths(ap.data);
          } catch {}
        }
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [engagementId]);

  const counts = {
    CRITICAL: findings.filter((f) => f.severity === "CRITICAL").length,
    HIGH: findings.filter((f) => f.severity === "HIGH").length,
    MEDIUM: findings.filter((f) => f.severity === "MEDIUM").length,
    LOW: findings.filter((f) => f.severity === "LOW").length,
  };

  async function verifyFix(f: Finding) {
    const fid = f.fingerprint || f.id || "unknown";
    setVerifying(fid);
    try {
      const res = await api.post(`/api/v1/findings/${fid}/verify-fix`);
      const data = res.data?.data ?? res.data;
      setFindings((prev) => prev.map((x) => (x.fingerprint === fid || x.id === fid ? { ...x, status: data.new_status || "RESOLVED", verified: data.verified } : x)));
      showToast("Fix verified successfully", "success");
    } catch (e: any) {
      showToast(e?.response?.data?.detail || "Verify failed");
    } finally { setVerifying(null); }
  }

  async function exportBounty() {
    if (!projectId) return;
    try {
      const res = await api.post(`/api/v1/projects/${projectId}/engagements/${engagementId}/export-bounty`, { platform: exportPlatform });
      setExportMd(res.data?.data?.markdown || JSON.stringify(res.data, null, 2));
    } catch (e: any) {
      setExportMd(e?.response?.data?.detail || "Export failed");
    }
  }

  async function downloadPdf() {
    if (!projectId) return;
    try {
      const res = await api.post(
        `/api/v1/projects/${projectId}/pentest/report?format=pdf`,
        { engagement_id: engagementId, targets: [], format: "json" },
        { responseType: "blob" }
      );
      const blob = new Blob([res.data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `report-${engagementId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      showToast("PDF requires an authorized engagement with scope rules. " + (e?.response?.data?.detail || ""));
    }
  }

  if (loading) return (
    <div className="flex items-center justify-center py-20">
      <Loader2 className="h-6 w-6 animate-spin text-[var(--primary)]" />
      <span className="ml-2 text-sm text-[var(--muted-foreground)]">Loading findings...</span>
    </div>
  );

  return (
    <div className="space-y-6">
      {toast && (
        <div className={`fixed top-4 right-4 z-50 text-sm rounded p-3 shadow-lg ${toast.type === "error" ? "text-red-400 bg-red-500/10 border border-red-500/20" : "text-green-400 bg-green-500/10 border border-green-500/20"}`}>
          {toast.msg}
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2"><Bug className="h-5 w-5 text-[var(--primary)]" /> Findings — {engagementId.slice(0, 8)}</h1>
          <p className="text-sm text-[var(--muted-foreground)]">CVSS v4.0 • OWASP/PCI-DSS • Passive PoC • Attack Path</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={downloadPdf}><Download className="h-4 w-4 mr-1" /> PDF</Button>
          <Button variant="outline" size="sm" onClick={() => setShowExport(true)}><ExternalLink className="h-4 w-4 mr-1" /> Export</Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => (
          <Card key={sev}>
            <CardHeader className="pb-2"><CardTitle className="text-xs">{sev}</CardTitle></CardHeader>
            <CardContent><div className="text-2xl font-bold">{counts[sev as keyof typeof counts]}</div></CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><Shield className="h-4 w-4 text-[var(--primary)]" /> Attack Path Chain</CardTitle></CardHeader>
        <CardContent>
          {attackPaths?.nodes?.length ? <AttackPathGraph nodes={attackPaths.nodes || []} links={attackPaths.links || []} /> : <p className="text-sm text-[var(--muted-foreground)]">No attack paths yet.</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Findings</CardTitle><CardDescription>{findings.length} finding{findings.length !== 1 ? "s" : ""}</CardDescription></CardHeader>
        <CardContent className="space-y-3">
          {findings.length === 0 ? (
            <p className="text-sm text-[var(--muted-foreground)] text-center py-6">No findings yet. Run a scan or check compliance data.</p>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
              <table className="w-full text-sm">
                <thead className="bg-[var(--muted)]/50 text-xs">
                  <tr><th className="text-left p-3">Finding</th><th className="text-left p-3">CVSS</th><th className="text-left p-3">Compliance</th><th className="text-left p-3">Host</th><th className="text-right p-3">Actions</th></tr>
                </thead>
                <tbody>
                  {findings.map((f) => (
                    <React.Fragment key={f.fingerprint}>
                      <tr className="border-t border-[var(--border)] hover:bg-[var(--muted)]/20">
                        <td className="p-3">
                          <div className="font-medium flex items-center gap-2">{f.title || f.template_id} {f.status === "RESOLVED" && <span className="text-xs px-1.5 py-0.5 rounded bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-1"><CheckCircle className="h-3 w-3" /> RESOLVED</span>}</div>
                          <div className="text-xs text-[var(--muted-foreground)]">{f.template_id}</div>
                        </td>
                        <td className="p-3"><span className={`text-xs px-2 py-1 rounded-full ${f.severity === "CRITICAL" ? "bg-red-900 text-red-100" : f.severity === "HIGH" ? "bg-red-600 text-white" : "bg-amber-600 text-white"}`}>{f.severity} {f.cvss_score ?? ""}</span></td>
                        <td className="p-3 text-xs">
                          {f.compliance ? (
                            <div className="space-y-1">
                              <div className="px-1.5 py-0.5 rounded bg-[#0f2a44] text-white inline-block text-[10px]">{f.compliance.owasp}</div>
                              <div className="text-[10px]">PCI {f.compliance.pci}</div>
                            </div>
                          ) : <span className="text-[var(--muted-foreground)]">—</span>}
                        </td>
                        <td className="p-3 text-xs">{f.host || "—"}</td>
                        <td className="p-3 text-right flex gap-1 justify-end">
                          <Button size="sm" variant="outline" onClick={() => setExpanded(expanded === f.fingerprint ? null : f.fingerprint!)}>{expanded === f.fingerprint ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />} PoC</Button>
                          <Button size="sm" onClick={() => verifyFix(f)} disabled={verifying === f.fingerprint}>{verifying === f.fingerprint ? <Loader2 className="h-3 w-3 animate-spin" /> : "Verify Fix"}</Button>
                        </td>
                      </tr>
                      {expanded === f.fingerprint && f.poc && (
                        <tr className="bg-[var(--muted)]/20"><td colSpan={5} className="p-3">
                          <div className="space-y-2">
                            <div className="text-xs font-medium">Passive PoC — Raw HTTP</div>
                            {f.poc.request && <pre className="bg-[#0a0a0a] text-[#e5e7eb] p-3 rounded text-xs overflow-auto max-h-40 whitespace-pre-wrap break-all border border-[var(--border)]">{f.poc.request}</pre>}
                            {f.poc.response && <pre className="bg-[#0a0a0a] text-[#e5e7eb] p-3 rounded text-xs overflow-auto max-h-40 whitespace-pre-wrap break-all border border-[var(--border)]">{f.poc.response}</pre>}
                            {f.poc.is_passive && <p className="text-[10px] text-[var(--muted-foreground)]">* Passive — no destructive payload executed.</p>}
                          </div>
                        </td></tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {showExport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setShowExport(false)}>
          <div onClick={(e) => e.stopPropagation()} className="w-full max-w-2xl">
            <Card>
              <CardHeader><CardTitle>Export to HackerOne / Bugcrowd</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <div className="flex gap-2">
                  {(["hackerone", "bugcrowd"] as const).map((p) => (
                    <Button key={p} variant={exportPlatform === p ? "default" : "outline"} size="sm" onClick={() => setExportPlatform(p)}>{p}</Button>
                  ))}
                  <Button size="sm" onClick={exportBounty}>Generate Markdown</Button>
                </div>
                {exportMd && <pre className="bg-[#0a0a0a] text-[#e5e7eb] p-3 rounded text-xs overflow-auto max-h-80 whitespace-pre-wrap border border-[var(--border)]">{exportMd}</pre>}
                <div className="flex justify-end"><Button variant="ghost" onClick={() => setShowExport(false)}>Close</Button></div>
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}

import React from "react";
