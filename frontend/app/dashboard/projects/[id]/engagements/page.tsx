"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ShieldAlert, Play, CheckCircle, Clock, Loader2 } from "lucide-react";

type Engagement = { id: string; name: string; project_id: string; status: string; created_at: string };

export default function EngagementsPage() {
  const params = useParams<{ id: string }>();
  const projectId = params.id as string;
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [name, setName] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [scans, setScans] = useState<Record<string, "Idle" | "Scanning" | "Completed">>({});

  async function load() {
    try {
      const res = await api.get("/api/v1/engagements/");
      const list: Engagement[] = res.data?.data ?? res.data;
      setEngagements((Array.isArray(list) ? list : []).filter((e) => e.project_id === projectId));
    } catch {}
  }
  useEffect(() => { load(); }, [projectId]);

  async function create() {
    if (!name.trim()) { setMsg("Name required"); return; }
    setMsg(null);
    try {
      await api.post("/api/v1/engagements/", { name: name.trim(), project_id: projectId });
      setName("");
      await load();
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || "Failed to create engagement");
    }
  }

  function triggerScan(engId: string) {
    setScans((s) => ({ ...s, [engId]: "Scanning" }));
    // Simulate real-time progress: in production this would poll GET /scans/{id} or websocket
    setTimeout(() => {
      setScans((s) => ({ ...s, [engId]: "Completed" }));
    }, 2500);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Engagements & Active Scans</h1>
        <p className="text-sm text-[var(--muted-foreground)]">POST /api/v1/engagements/ — each engagement is isolated to its project</p>
      </div>

      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 flex gap-3">
        <ShieldAlert className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-sm">
          <div className="font-medium text-amber-300">Scope Guard — Automatic Protection</div>
          <div className="text-amber-200/80 text-xs mt-1">Targets ending in <code className="bg-black/30 px-1 rounded">.gov</code>, <code className="bg-black/30 px-1 rounded">.mil</code>, <code className="bg-black/30 px-1 rounded">.edu</code> are <strong>always blocked</strong> by <code>global_exclusions.is_excluded</code> — even if you add an include rule. All scan requests pass through <code>scope_validator.validate_target</code>.</div>
        </div>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-base">Initiate Security Assessment</CardTitle><CardDescription>Creates a new engagement under this project (status → draft)</CardDescription></CardHeader>
        <CardContent className="flex gap-2">
          <div className="flex-1 space-y-2">
            <Label>Engagement Name *</Label>
            <Input placeholder="Q4 External Perimeter" value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && create()} />
          </div>
          <Button onClick={create} className="self-end"><Play className="h-4 w-4 mr-1" /> Create</Button>
        </CardContent>
        {msg && <p className="px-6 pb-4 text-sm text-red-400">{msg}</p>}
      </Card>

      <div className="space-y-3">
        {engagements.length === 0 ? (
          <Card><CardContent className="p-6 text-sm text-[var(--muted-foreground)]">No engagements yet. Create one to trigger a scan.</CardContent></Card>
        ) : (
          engagements.map((en) => {
            const st = scans[en.id] || "Idle";
            return (
              <Card key={en.id}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">{en.name}</div>
                      <div className="text-xs text-[var(--muted-foreground)]">{en.id} • {en.status} • {new Date(en.created_at).toLocaleString()}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`inline-flex items-center gap-1 text-xs px-2 py-1 rounded-full border ${st === "Idle" ? "bg-[var(--muted)] text-[var(--muted-foreground)]" : st === "Scanning" ? "bg-cyan-500/20 text-cyan-400 border-cyan-500/30" : "bg-green-500/20 text-green-400 border-green-500/30"}`}>
                        {st === "Scanning" ? <Loader2 className="h-3 w-3 animate-spin" /> : st === "Completed" ? <CheckCircle className="h-3 w-3" /> : <Clock className="h-3 w-3" />} {st}
                      </span>
                      <Button size="sm" variant="outline" onClick={() => triggerScan(en.id)} disabled={st === "Scanning"}>
                        {st === "Completed" ? "Re-run" : "Trigger Scan"}
                      </Button>
                    </div>
                  </div>
                  {st === "Scanning" && <div className="mt-3 h-1.5 w-full bg-[var(--muted)] rounded-full overflow-hidden"><div className="h-full bg-[var(--primary)] animate-pulse w-2/3" /></div>}
                  <p className="text-xs text-[var(--muted-foreground)] mt-2">Real-time status would poll <code>GET /api/v1/scans/{`{id}`}</code> or websocket — mocked here for demo.</p>
                </CardContent>
              </Card>
            );
          })
        )}
      </div>
    </div>
  );
}
