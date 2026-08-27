"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Shield, BadgeCheck, BadgeAlert, ArrowLeft, Plus } from "lucide-react";

type Project = { id: string; name: string; description?: string; owner_id: string; created_at: string };
type Engagement = { id: string; name: string; project_id: string; status: string; created_at: string };

export default function ProjectDetailsPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const projectId = params.id as string;
  const [project, setProject] = useState<Project | null>(null);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [msg, setMsg] = useState<string | null>(null);
  const [verifying, setVerifying] = useState<string | null>(null);
  const [targetDomain, setTargetDomain] = useState("");
  const [method, setMethod] = useState<"dns_txt" | "bug_bounty_program">("dns_txt");
  const [bountyPlatform, setBountyPlatform] = useState("hackerone");
  const [bountyHandle, setBountyHandle] = useState("");
  const [newEngName, setNewEngName] = useState("");
  const [creating, setCreating] = useState(false);

  async function load() {
    try {
      const p = await api.get(`/api/v1/projects/${projectId}`);
      setProject(p.data);
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || "Failed to load project");
    }
    try {
      const res = await api.get("/api/v1/engagements/");
      const list: Engagement[] = res.data?.data ?? res.data;
      setEngagements((Array.isArray(list) ? list : []).filter((en) => en.project_id === projectId));
    } catch {}
  }
  useEffect(() => { load(); }, [projectId]);

  async function createEngagement() {
    if (!newEngName.trim()) { setMsg("Engagement name required"); return; }
    setCreating(true); setMsg(null);
    try {
      await api.post("/api/v1/engagements/", { name: newEngName.trim(), project_id: projectId });
      setNewEngName("");
      setMsg("Engagement created — now verify it below");
      await load();
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || "Failed to create engagement");
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
      setMsg(`Verified: ${res.data?.method || method} — ${res.data?.verified ? "Verified" : "Pending"}`);
      await load();
    } catch (e: any) {
      const detail = e?.response?.data?.detail || e.message || "Verification failed";
      setMsg(String(detail));
    } finally { setVerifying(null); }
  }

  if (!project) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" onClick={() => router.push("/dashboard/projects")}><ArrowLeft className="h-4 w-4 mr-1" /> Back</Button>
        {msg ? <p className="text-sm text-red-400">{msg}</p> : <p className="text-sm text-[var(--muted-foreground)]">Loading...</p>}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Button variant="ghost" size="sm" onClick={() => router.push("/dashboard/projects")}><ArrowLeft className="h-4 w-4 mr-1" /> Back to Projects</Button>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Shield className="h-5 w-5 text-[var(--primary)]" /> {project.name}</CardTitle>
          <CardDescription>{project.description || "No description"} • {project.id}</CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-[var(--muted-foreground)]">Owner: {project.owner_id} • Created {new Date(project.created_at).toLocaleString()}</CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Authorization</CardTitle>
          <CardDescription>POST /api/v1/engagements/{`{id}`}/authorization — DNS TXT or Bug Bounty proof. Badge reflects <code>verified</code>.</CardDescription>
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
                    <option value="hackerone">hackerone</option>
                    <option value="bugcrowd">bugcrowd</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <Label>Program Handle *</Label>
                  <Input placeholder="my-program" value={bountyHandle} onChange={(e) => setBountyHandle(e.target.value)} />
                </div>
              </>
            )}
          </div>
          <p className="text-xs text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded p-2">Scope Guard: .gov/.mil/.edu are always blocked (global exclusions) even if you include them.</p>
          {msg && <p className="text-sm bg-[var(--muted)] border border-[var(--border)] rounded p-2">{msg}</p>}
        </CardContent>
      </Card>

      <div>
        <h2 className="font-semibold mb-3">Engagements in this project</h2>
        <Card className="mb-4">
          <CardHeader className="pb-2"><CardTitle className="text-base">Create Engagement</CardTitle><CardDescription>POST /api/v1/engagements/ — will start as draft, then verify above</CardDescription></CardHeader>
          <CardContent className="flex gap-2">
            <Input placeholder="Q4 External Perimeter" value={newEngName} onChange={(e) => setNewEngName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && createEngagement()} />
            <Button onClick={createEngagement} disabled={creating}><Plus className="h-4 w-4 mr-1" /> {creating ? "..." : "Create"}</Button>
          </CardContent>
        </Card>
        {engagements.length === 0 ? (
          <Card><CardContent className="p-6 text-sm text-[var(--muted-foreground)]">No engagements yet. Use the form above to create your first one.</CardContent></Card>
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
                        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30"><BadgeAlert className="h-3 w-3" /> Unverified</span>
                      )}
                      <span className="text-xs px-2 py-0.5 rounded bg-[var(--muted)]">{en.status}</span>
                    </div>
                    <div className="text-xs text-[var(--muted-foreground)]">{en.id} • {new Date(en.created_at).toLocaleString()}</div>
                  </div>
                  <div className="flex gap-2">
                    <Button size="sm" variant="outline" onClick={() => verify(en.id)} disabled={verifying === en.id}>{verifying === en.id ? "..." : "Verify"}</Button>
                    <Link href={`/dashboard/projects/${projectId}/engagements`}><Button size="sm" variant="ghost">Manage →</Button></Link>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
