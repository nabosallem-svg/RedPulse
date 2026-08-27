"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Shield, FolderKanban, Target, FileText, Activity, AlertTriangle } from "lucide-react";

export default function DashboardPage() {
  const [stats, setStats] = useState({ projects: 0, engagements: 0, reports: 0 });
  useEffect(() => {
    async function load() {
      try {
        const [proj, eng] = await Promise.all([
          api.get("/api/v1/projects/").then(r => r.data).catch(() => ({ data: [] })),
          api.get("/api/v1/engagements/").then(r => r.data).catch(() => ({ data: [] })),
        ]);
        const pCount = Array.isArray(proj) ? proj.length : (proj?.data?.length ?? proj?.total ?? 0);
        const eCount = Array.isArray(eng) ? eng.length : (eng?.data?.length ?? eng?.total ?? 0);
        setStats({ projects: pCount, engagements: eCount, reports: 0 });
      } catch {}
    }
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-sm text-[var(--muted-foreground)]">Controlled Pentesting — all scans are targeted via scope_validator</p>
      </div>

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
            <CardTitle className="text-sm font-medium">Reports</CardTitle>
            <FileText className="h-4 w-4 text-[var(--primary)]" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.reports}</div>
            <p className="text-xs text-[var(--muted-foreground)]">PDF + CVSS v4.0 + PoC</p>
            <Button variant="outline" size="sm" className="mt-3 w-full" disabled>Coming soon</Button>
          </CardContent>
        </Card>
      </div>

      <Card className="border-[var(--primary)]/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Shield className="h-5 w-5 text-[var(--primary)]" /> Security Posture</CardTitle>
          <CardDescription>Passive PoC only • No destructive exploits • Scope enforced</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-4 text-sm">
          <span className="flex items-center gap-2"><Activity className="h-4 w-4 text-green-400" /> API: {process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}</span>
          <span className="flex items-center gap-2 text-amber-400"><AlertTriangle className="h-4 w-4" /> Controlled</span>
        </CardContent>
      </Card>
    </div>
  );
}
