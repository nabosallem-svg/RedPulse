"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Target, Loader2, Shield, Globe, AlertTriangle, CheckCircle2, ExternalLink } from "lucide-react";

export default function AllEngagementsPage() {
  const [list, setList] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [scopeMap, setScopeMap] = useState<Record<string, any[]>>({});
  const [bountyPlatform, setBountyPlatform] = useState<"hackerone" | "bugcrowd">("hackerone");
  const [bountyHandle, setBountyHandle] = useState("");
  const [bountyLoading, setBountyLoading] = useState<string | null>(null);
  const [bountyResult, setBountyResult] = useState<Record<string, any>>({});

  useEffect(() => {
    async function load() {
      try {
        const res = await api.get("/api/v1/engagements/");
        const data = res.data?.data ?? res.data;
        setList(Array.isArray(data) ? data : []);
      } catch (e: any) {
        setError(e?.response?.data?.detail || "Failed to load engagements");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  async function loadScope(engId: string) {
    try {
      const res = await api.get(`/api/v1/engagements/${engId}/scope`);
      setScopeMap(prev => ({ ...prev, [engId]: Array.isArray(res.data) ? res.data : [] }));
    } catch (e: any) {
      setScopeMap(prev => ({ ...prev, [engId]: [] }));
    }
  }

  async function handleBountyFetch(engId: string) {
    if (!bountyHandle.trim()) {
      setBountyResult(prev => ({ ...prev, [engId]: { error: "أدخل Program Handle (مثال: uber)" } }));
      return;
    }
    setBountyLoading(engId);
    setBountyResult(prev => ({ ...prev, [engId]: {} }));
    try {
      const res = await api.post(`/api/v1/engagements/${engId}/authorization`, {
        method: "bug_bounty_program",
        bounty_platform: bountyPlatform,
        bounty_program_handle: bountyHandle.trim(),
        target_domain: "",
      });
      setBountyResult(prev => ({ ...prev, [engId]: { success: true, data: res.data } }));
      // refresh scope after success
      loadScope(engId);
    } catch (e: any) {
      const detail = e?.response?.data?.detail || "Failed to fetch bounty scope";
      setBountyResult(prev => ({ ...prev, [engId]: { error: detail } }));
    } finally {
      setBountyLoading(null);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--primary)]" />
        <span className="ml-2 text-sm text-[var(--muted-foreground)]">Loading engagements...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold flex items-center gap-2"><Target className="h-5 w-5 text-[var(--primary)]" /> All Engagements — Program Intelligence</h1>
        <p className="text-sm text-[var(--muted-foreground)]">كل Engagement مربوط بـ <code className="bg-[var(--muted)] px-1 rounded">POST /api/v1/engagements/{`{id}`}/authorization</code> لسحب الـ scope الرسمي من HackerOne/Bugcrowd</p>
      </div>
      {error && <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded p-2">{error}</p>}
      <div className="grid gap-3">
        {list.length === 0 ? <Card><CardContent className="p-6 text-sm text-[var(--muted-foreground)]">No engagements. Create one from a project → ثم اربطه بـ HackerOne/Bugcrowd هنا.</CardContent></Card> : list.map((e: any) => (
          <Card key={e.id} className={expanded === e.id ? "border-[var(--primary)]/40" : "hover:border-[var(--primary)]/20"}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base flex items-center gap-2"><Target className="h-4 w-4 text-[var(--primary)]" />{e.name}</CardTitle>
                <span className="text-xs px-2 py-1 rounded bg-[var(--muted)] border border-[var(--border)]">{e.status}</span>
              </div>
              <CardDescription className="text-xs font-mono">{e.id} • project {e.project_id}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex gap-2 flex-wrap">
                <Link href={`/dashboard/engagements/${e.id}`}><Button size="sm" variant="outline">View Findings</Button></Link>
                <Button size="sm" variant="outline" onClick={() => { const ne = expanded === e.id ? null : e.id; setExpanded(ne); if (ne) loadScope(e.id); }}>
                  <Globe className="h-3 w-3 mr-1" /> {expanded === e.id ? "إخفاء" : "Program Intelligence (HackerOne/Bugcrowd)"}
                </Button>
                <Link href={`/dashboard/projects/${e.project_id}/engagements`}><Button size="sm" variant="ghost"><ExternalLink className="h-3 w-3 mr-1" /> Manage Scopes</Button></Link>
              </div>

              {expanded === e.id && (
                <div className="space-y-3 rounded border border-[var(--border)] bg-[var(--muted)]/20 p-3">
                  <div className="text-sm font-medium flex items-center gap-2"><Shield className="h-4 w-4 text-[var(--primary)]" /> ربط ببرنامج Bug Bounty — سحب Scope الرسمي</div>
                  <p className="text-xs text-[var(--muted-foreground)]">ينادي <code className="bg-black/50 px-1 rounded">POST /api/v1/engagements/{e.id}/authorization</code> مع <code className="bg-black/50 px-1 rounded">method=bug_bounty_program</code></p>
                  
                  <div className="grid gap-3 md:grid-cols-3">
                    <div>
                      <Label className="text-xs">Platform</Label>
                      <select className="w-full mt-1 rounded-md border border-[var(--border)] bg-[var(--background)] px-3 py-2 text-sm" value={bountyPlatform} onChange={ev => setBountyPlatform(ev.target.value as any)}>
                        <option value="hackerone">HackerOne</option>
                        <option value="bugcrowd">Bugcrowd</option>
                      </select>
                    </div>
                    <div className="md:col-span-2">
                      <Label className="text-xs">Program Handle</Label>
                      <div className="flex gap-2 mt-1">
                        <Input placeholder={bountyPlatform === "hackerone" ? "uber, shopify..." : "tesla, ..."} value={bountyHandle} onChange={ev => setBountyHandle(ev.target.value)} />
                        <Button onClick={() => handleBountyFetch(e.id)} disabled={bountyLoading === e.id} className="shrink-0 bg-[var(--primary)]">
                          {bountyLoading === e.id ? <Loader2 className="h-4 w-4 animate-spin" /> : "سحب Scope"}
                        </Button>
                      </div>
                    </div>
                  </div>

                  {bountyResult[e.id]?.error && (
                    <div className="text-xs text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded p-2 flex gap-2">
                      <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0" />
                      <div>
                        <div>{bountyResult[e.id].error}</div>
                        {bountyResult[e.id].error.includes("No platform connection") && (
                          <div className="mt-1 text-[11px] text-[var(--muted-foreground)]">لم تربط حساب {bountyPlatform} بعد — الـ API يتحقق من <code className="bg-black/50 px-1 rounded">PlatformConnection</code>. للتجربة: أضف Scope يدويًا من Scans → إضافة النطاق للـ Scope (ينادي POST /api/v1/engagements/{`{id}`}/scope).</div>
                        )}
                      </div>
                    </div>
                  )}
                  {bountyResult[e.id]?.success && (
                    <div className="text-xs text-green-400 bg-green-500/10 border border-green-500/20 rounded p-2 flex gap-2"><CheckCircle2 className="h-3 w-3 mt-0.5" /> تم سحب Scope وربط البرنامج — الحالة أصبحت authorized. الـ Scope الجديد يظهر أدناه.</div>
                  )}

                  <div>
                    <div className="text-xs font-medium mb-1">الـ Scope الحالي (من <code className="bg-black/50 px-1 rounded">GET /api/v1/engagements/{e.id}/scope</code>):</div>
                    {(scopeMap[e.id] || []).length === 0 ? (
                      <p className="text-xs text-[var(--muted-foreground)]">لا يوجد scope بعد — أضف نطاق من Scans أو عبر البounty fetch.</p>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {scopeMap[e.id].map((r: any) => (
                          <span key={r.id} className={`text-xs px-2 py-1 rounded border ${r.is_include ? "bg-green-500/10 border-green-500/20 text-green-300" : "bg-red-500/10 border-red-500/20 text-red-300"}`}>
                            {r.is_include ? "+" : "−"} {r.target}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
