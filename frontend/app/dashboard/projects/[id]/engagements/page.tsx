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
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const res = await api.get("/api/v1/engagements/");
      const list: Engagement[] = res.data?.data ?? res.data;
      setEngagements((Array.isArray(list) ? list : []).filter((e) => e.project_id === projectId));
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || "Failed to load engagements");
    } finally { setLoading(false); }
  }
  useEffect(() => { load(); }, [projectId]);

  async function create() {
    if (!name.trim()) { setMsg("Name required"); return; }
    setMsg(null); setCreating(true);
    try {
      await api.post("/api/v1/engagements/", { name: name.trim(), project_id: projectId });
      setName("");
      await load();
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || "Failed to create engagement");
    } finally { setCreating(false); }
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
        <h1 className="text-xl font-semibold">Engagements</h1>
        <p className="text-sm text-[var(--muted-foreground)]">Each engagement is isolated to its project</p>
      </div>

      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 flex gap-3">
        <ShieldAlert className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-sm">
          <div className="font-medium text-amber-300">Scope Guard</div>
          <div className="text-amber-200/80 text-xs mt-1">.gov/.mil/.edu domains are always blocked by global exclusions.</div>
        </div>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-base">Create Engagement</CardTitle></CardHeader>
        <CardContent className="flex gap-2">
          <div className="flex-1 space-y-2">
            <Label>Name *</Label>
            <Input placeholder="Q4 External Perimeter" value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && create()} disabled={creating} />
          </div>
          <Button onClick={create} disabled={creating} className="self-end"><Play className="h-4 w-4 mr-1" /> {creating ? "..." : "Create"}</Button>
        </CardContent>
        {msg && <p className="px-6 pb-4 text-sm text-red-400">{msg}</p>}
      </Card>

      <div className="space-y-3">
        {engagements.length === 0 ? (
          <Card><CardContent className="p-6 text-sm text-[var(--muted-foreground)]">No engagements yet. Create one to get started.</CardContent></Card>
        ) : (
          engagements.map((en) => (
            <Card key={en.id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium">{en.name}</div>
                    <div className="text-xs text-[var(--muted-foreground)]">{en.status} • {new Date(en.created_at).toLocaleString()}</div>
                  </div>
                  <span className={`inline-flex items-center gap-1 text-xs px-2 py-1 rounded-full border ${en.status === "authorized" ? "bg-green-500/20 text-green-400 border-green-500/30" : "bg-[var(--muted)] text-[var(--muted-foreground)]"}`}>
                    {en.status === "authorized" ? <CheckCircle className="h-3 w-3" /> : <Clock className="h-3 w-3" />} {en.status}
                  </span>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
