"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Shield, BadgeCheck, BadgeAlert, ArrowLeft, Plus, Loader2 } from "lucide-react";

type Project = { id: string; name: string; description?: string; owner_id: string; created_at: string };
type Engagement = { id: string; name: string; project_id: string; status: string; created_at: string };
type ScopeRule = { id: string; target: string; is_include: boolean; source: string; created_at: string };

export default function ProjectDetailsPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const projectId = params.id as string;
  const [project, setProject] = useState<Project | null>(null);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [scopeRules, setScopeRules] = useState<ScopeRule[]>([]);
  const [selectedEngId, setSelectedEngId] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [msgType, setMsgType] = useState<"error" | "success">("error");
  const [verifying, setVerifying] = useState<string | null>(null);
  const [targetDomain, setTargetDomain] = useState("");
  const [method, setMethod] = useState<"dns_txt" | "bug_bounty_program">("dns_txt");
  const [bountyPlatform, setBountyPlatform] = useState("hackerone");
  const [bountyHandle, setBountyHandle] = useState("");
  const [newEngName, setNewEngName] = useState("");
  const [creating, setCreating] = useState(false);
  const [scopeTarget, setScopeTarget] = useState("");
  const [scopeIsInclude, setScopeIsInclude] = useState(true);
  const [addingScope, setAddingScope] = useState(false);
  const [loading, setLoading] = useState(true);

  function showMsg(text: string, type: "error" | "success" = "error") {
    setMsg(text);
    setMsgType(type);
    if (type === "success") setTimeout(() => setMsg(null), 4000);
  }

  async function load() {
    setLoading(true);
    try {
      const p = await api.get(`/api/v1/projects/${projectId}`);
      setProject(p.data);
    } catch (e: any) {
      showMsg(e?.response?.data?.detail || "Failed to load project");
    }
    try {
      const res = await api.get("/api/v1/engagements/");
      const list: Engagement[] = res.data?.data ?? res.data;
      setEngagements((Array.isArray(list) ? list : []).filter((en) => en.project_id === projectId));
    } catch {}
    setLoading(false);
  }
  useEffect(() => { load(); }, [projectId]);

  async function createEngagement() {
    if (!newEngName.trim()) { showMsg("Engagement name required"); return; }
    setCreating(true); setMsg(null);
    try {
      await api.post("/api/v1/engagements/", { name: newEngName.trim(), project_id: projectId });
      setNewEngName("");
      showMsg("Engagement created", "success");
      await load();
    } catch (e: any) {
      showMsg(e?.response?.data?.detail || "Failed to create engagement");
    } finally { setCreating(false); }
  }

  async function verify(engId: string) {
    setVerifying(engId); setMsg(null);
    try {
      const payload: any = { method };
      if (method === "dns_txt") {
        if (!targetDomain.trim()) throw new Error("target_domain required");
        payload.target_domain = targetDomain.trim();
      } else {
        payload.bounty_platform = bountyPlatform;
        payload.bounty_program_handle = bountyHandle.trim();
        if (!payload.bounty_program_handle) throw new Error("bounty_program_handle required");
      }
      const res = await api.post(`/api/v1/engagements/${engId}/authorization`, payload);
      showMsg(`Authorization: ${res.data?.verified ? "Verified" : "Pending DNS verification"}`, "success");
      await load();
    } catch (e: any) {
      const detail = e?.response?.data?.detail || e.message || "Verification failed";
      showMsg(String(detail));
    } finally { setVerifying(null); }
  }

  async function loadScope(engId: string) {
    setSelectedEngId(engId);
    try {
      const res = await api.get(`/api/v1/engagements/${engId}/scope`);
      setScopeRules(Array.isArray(res.data) ? res.data : []);
    } catch { setScopeRules([]); }
  }

  async function addScopeRule() {
    if (!selectedEngId || !scopeTarget.trim()) return;
    setAddingScope(true);
    try {
      await api.post(`/api/v1/engagements/${selectedEngId}/scope`, {
        target: scopeTarget.trim(),
        is_include: scopeIsInclude,
      });
      setScopeTarget("");
      await loadScope(selectedEngId);
      showMsg("Scope rule added", "success");
    } catch (e: any) {
      showMsg(e?.response?.data?.detail || "Failed to add scope rule");
    } finally { setAddingScope(false); }
  }

  if (loading) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" onClick={() => router.push("/dashboard/projects")}><ArrowLeft className="h-4 w-4 mr-1" /> Back</Button>
        <div className="flex items-center justify-center py-20">
          <Loader2 className="h-6 w-6 animate-spin text-[var(--primary)]" />
          <span className="ml-2 text-sm text-[var(--muted-foreground)]">Loading project...</span>
        </div>
      </div>
    );
  }

  if (!project && msg) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" onClick={() => router.push("/dashboard/projects")}><ArrowLeft className="h-4 w-4 mr-1" /> Back</Button>
        <p className="text-sm text-red-400">{msg}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Button variant="ghost" size="sm" onClick={() => router.push("/dashboard/projects")}><ArrowLeft className="h-4 w-4 mr-1" /> Back to Projects</Button>

      {project && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Shield className="h-5 w-5 text-[var(--primary)]" /> {project.name}</CardTitle>
            <CardDescription>{project.description || "No description"} • {project.id}</CardDescription>
          </CardHeader>
          <CardContent className="text-sm text-[var(--muted-foreground)]">Owner: {project.owner_id} • Created {new Date(project.created_at).toLocaleString()}</CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Authorization</CardTitle>
          <CardDescription>DNS TXT or Bug Bounty proof. Badge reflects verification status.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>Method</Label>
              <select value={method} onChange={(e) => setMethod(e.target.value as any)} className="flex h-10 w-full rounded-md border border-[var(--border)] bg-[var(--input)] px-3 py-2 text-sm">
                <option value="dns_txt">DNS TXT (self-owned)</option>
                <option value="bug_bounty_program">Bug Bounty Program</option>
              </select>
            </div>
            {method === "dns_txt" ? (
              <div className="space-y-2">
                <Label>Target Domain *</Label>
                <Input placeholder="example.com" value={targetDomain} onChange={(e) => setTargetDomain(e.target.value)} />
              </div>
            ) : (
              <>
                <div className="space-y-2">
                  <Label>Platform</Label>
                  <select value={bountyPlatform} onChange={(e) => setBountyPlatform(e.target.value)} className="flex h-10 w-full rounded-md border border-[var(--border)] bg-[var(--input)] px-3 py-2 text-sm">
                    <option value="hackerone">HackerOne</option>
                    <option value="bugcrowd">Bugcrowd</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <Label>Program Handle *</Label>
                  <Input placeholder="my-program" value={bountyHandle} onChange={(e) => setBountyHandle(e.target.value)} />
                </div>
              </>
            )}
          </div>
          <p className="text-xs text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded p-2">.gov/.mil/.edu domains are always blocked (global exclusions).</p>
          {msg && (
            <p className={`text-sm rounded p-2 ${msgType === "error" ? "text-red-400 bg-red-500/10 border border-red-500/20" : "text-green-400 bg-green-500/10 border border-green-500/20"}`}>{msg}</p>
          )}
        </CardContent>
      </Card>

      <div>
        <h2 className="font-semibold mb-3">Engagements</h2>
        <Card className="mb-4">
          <CardHeader className="pb-2"><CardTitle className="text-base">Create Engagement</CardTitle></CardHeader>
          <CardContent className="flex gap-2">
            <Input placeholder="Q4 External Perimeter" value={newEngName} onChange={(e) => setNewEngName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && createEngagement()} disabled={creating} />
            <Button onClick={createEngagement} disabled={creating}><Plus className="h-4 w-4 mr-1" /> {creating ? "..." : "Create"}</Button>
          </CardContent>
        </Card>
        {engagements.length === 0 ? (
          <Card><CardContent className="p-6 text-sm text-[var(--muted-foreground)]">No engagements yet.</CardContent></Card>
        ) : (
          <div className="grid gap-3">
            {engagements.map((en) => (
              <Card key={en.id}>
                <CardContent className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div>
                    <div className="font-medium flex items-center gap-2">
                      {en.name}
                      {en.status === "authorized" || en.status === "verified" ? (
                        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-green-500/20 text-green-400 border border-green-500/30"><BadgeCheck className="h-3 w-3" /> Verified</span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30"><BadgeAlert className="h-3 w-3" /> {en.status}</span>
                      )}
                    </div>
                    <div className="text-xs text-[var(--muted-foreground)]">{new Date(en.created_at).toLocaleString()}</div>
                  </div>
                  <div className="flex gap-2">
                    <Button size="sm" variant="outline" onClick={() => verify(en.id)} disabled={verifying === en.id}>{verifying === en.id ? <Loader2 className="h-3 w-3 animate-spin" /> : "Verify"}</Button>
                    <Button size="sm" variant="ghost" onClick={() => loadScope(en.id)}>Scope</Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      {selectedEngId && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Scope Rules — Engagement {selectedEngId.slice(0, 8)}</CardTitle>
            <CardDescription>Include/exclude targets. Patterns like *.example.com are supported.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2 items-end">
              <div className="flex-1 space-y-1">
                <Label>Target Pattern</Label>
                <Input placeholder="*.example.com" value={scopeTarget} onChange={(e) => setScopeTarget(e.target.value)} disabled={addingScope} />
              </div>
              <div className="space-y-1">
                <Label>Type</Label>
                <select value={scopeIsInclude ? "include" : "exclude"} onChange={(e) => setScopeIsInclude(e.target.value === "include")} className="flex h-10 rounded-md border border-[var(--border)] bg-[var(--input)] px-3 py-2 text-sm">
                  <option value="include">Include</option>
                  <option value="exclude">Exclude</option>
                </select>
              </div>
              <Button onClick={addScopeRule} disabled={addingScope || !scopeTarget.trim()}>{addingScope ? "..." : "Add"}</Button>
            </div>
            {scopeRules.length === 0 ? (
              <p className="text-sm text-[var(--muted-foreground)]">No scope rules yet. Add include/exclude patterns above.</p>
            ) : (
              <div className="space-y-1">
                {scopeRules.map((r) => (
                  <div key={r.id} className="flex items-center gap-2 text-sm p-2 rounded bg-[var(--muted)]/50">
                    <span className={`text-xs px-1.5 py-0.5 rounded ${r.is_include ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}>{r.is_include ? "INCLUDE" : "EXCLUDE"}</span>
                    <code className="text-xs">{r.target}</code>
                    <span className="text-xs text-[var(--muted-foreground)] ml-auto">{r.source}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
