"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Target } from "lucide-react";

export default function AllEngagementsPage() {
  const [list, setList] = useState<any[]>([]);
  useEffect(() => {
    async function load() {
      try {
        const res = await api.get("/api/v1/engagements/");
        const data = res.data?.data ?? res.data;
        setList(Array.isArray(data) ? data : []);
      } catch {}
    }
    load();
  }, []);
  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold flex items-center gap-2"><Target className="h-5 w-5 text-[var(--primary)]" /> All Engagements</h1>
      <p className="text-sm text-[var(--muted-foreground)]">All engagements across your projects — click to view findings</p>
      <div className="grid gap-3">
        {list.length === 0 ? <Card><CardContent className="p-6 text-sm text-[var(--muted-foreground)]">No engagements. Create one from a project.</CardContent></Card> : list.map((e: any) => (
          <Link key={e.id} href={`/dashboard/engagements/${e.id}`}>
            <Card className="hover:border-[var(--primary)]/40 cursor-pointer">
              <CardHeader className="pb-2"><CardTitle className="text-base">{e.name}</CardTitle></CardHeader>
              <CardContent className="text-xs text-[var(--muted-foreground)]">{e.id} • {e.status} • {e.project_id}</CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
