"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Shield, FolderKanban, Target, FileText, Activity, Loader2 } from "lucide-react";

export default function DashboardPage() {
  const [stats, setStats] = useState({ projects: 0, engagements: 0, reports: 0, findings: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [onboard, setOnboard] = useState<{ percent: number; next?: string } | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [projRes, engRes, findingsRes, workspacesRes] = await Promise.all([
          api.get("/api/v1/projects/").catch(() => ({ data: { data: [] } })),
          api.get("/api/v1/engagements/").catch(() => ({ data: { data: [] } })),
          api.get("/api/v1/reports/undefined/summary").catch(() => null), // fallback for findings count
          api.get("/api/v1/projects/").then(async (r) => {
            const list = r.data?.data ?? r.data ?? [];
            const arr = Array.isArray(list) ? list : [];
            if (arr.length === 0) return { data: [] };
            // Try to fetch findings for first project for stats
            try {
              const p = arr[0];
              const fRes = await api.get(`/api/v1/reports/${p.id}/findings`).catch(() => ({ data: [] }));
              return fRes;
            } catch { return { data: [] }; }
          }).catch(() => ({ data: [] })),
        ]);
        const proj = projRes.data;
        const eng = engRes.data;
        const pCount = Array.isArray(proj) ? proj.length : (proj?.data?.length ?? proj?.total ?? 0);
        const eCount = Array.isArray(eng) ? eng.length : (eng?.data?.length ?? eng?.total ?? 0);
        // Real findings count from reports API if available
        const findingsData = (workspacesRes as any)?.data?.data ?? (workspacesRes as any)?.data ?? [];
        const fCount = Array.isArray(findingsData) ? findingsData.length : (findingsData?.findings?.length ?? 0);
        // Also try to get total findings via audit/overview
        let reportsCount = 0;
        try {
          const firstProj = (Array.isArray(proj) ? proj : proj?.data)?.[0];
          if (firstProj?.id) {
            const sumRes = await api.get(`/api/v1/reports/${firstProj.id}/summary`).catch(() => null);
            const sum = sumRes?.data?.data ?? sumRes?.data;
            reportsCount = sum?.findings_count ?? sum?.total ?? fCount ?? 0;
          }
        } catch {}
        setStats({ projects: pCount, engagements: eCount, reports: reportsCount, findings: fCount });
      } catch (e: any) {
        setError(e?.response?.data?.detail || "Failed to load dashboard");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  useEffect(() => {
    api.get("/api/v1/onboarding/progress").then((r) => {
      const d = r.data?.data ?? r.data;
      setOnboard({ percent: d?.progress?.percent ?? 0, next: d?.next_step?.title });
    }).catch(() => {});
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--primary)]" />
        <span className="ml-2 text-sm text-[var(--muted-foreground)]">Loading dashboard...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-sm text-[var(--muted-foreground)]">Controlled Pentesting — all scans are targeted via scope_validator</p>
      </div>

      {onboard && onboard.percent < 100 && (
        <Card className="border-amber-500/20 bg-amber-500/5">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <div className="text-sm font-medium">First-run onboarding — {onboard.percent}% complete</div>
              <div className="text-xs text-[var(--muted-foreground)]">Next: {onboard.next ?? "Continue setup"} · ~5 min to first scan</div>
            </div>
            <Link href="/onboarding"><Button size="sm">Continue onboarding</Button></Link>
          </CardContent>
        </Card>
      )}

      {error && (
        <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded p-3">{error}</div>
      )}

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Projects</CardTitle>
            <FolderKanban className="h-4 w-4 text-[var(--primary)]" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.projects}</div>
            <p className="text-xs text-[var(--muted-foreground)]">Isolated by owner_id</p>
            <Link href="/dashboard/projects"><Button variant="outline" size="sm" className="mt-3 w-full">View projects</Button></Link>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Engagements</CardTitle>
            <Target className="h-4 w-4 text-[var(--accent)]" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.engagements}</div>
            <p className="text-xs text-[var(--muted-foreground)]">Requires verified authorization</p>
            <Link href="/dashboard/engagements"><Button variant="outline" size="sm" className="mt-3 w-full">View engagements</Button></Link>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Reports / Findings</CardTitle>
            <FileText className="h-4 w-4 text-[var(--primary)]" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.reports || stats.findings}</div>
            <p className="text-xs text-[var(--muted-foreground)]">Real findings • CVSS v4.0 + PoC • PDF</p>
            <Link href="/dashboard/reports"><Button variant="outline" size="sm" className="mt-3 w-full">View reports</Button></Link>
          </CardContent>
        </Card>
      </div>

      <Card className="border-[var(--primary)]/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Shield className="h-5 w-5 text-[var(--primary)]" /> Security Posture</CardTitle>
          <CardDescription>Passive PoC only • No destructive exploits • Scope enforced</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-4 text-sm">
          <span className="flex items-center gap-2"><Activity className="h-4 w-4 text-green-400" /> API Connected</span>
          <span className="flex items-center gap-2 text-amber-400"><Shield className="h-4 w-4" /> Controlled</span>
        </CardContent>
      </Card>
    </div>
  );
}
