"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { FolderKanban, Plus, Search, ChevronLeft, ChevronRight, Loader2 } from "lucide-react";

type Project = { id: string; name: string; description?: string; owner_id: string; created_at: string };

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [meta, setMeta] = useState({ page: 1, per_page: 50, total: 0, pages: 1 });
  const [page, setPage] = useState(1);
  const [q, setQ] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [loading, setLoading] = useState(false);
  const [pageLoading, setPageLoading] = useState(true);
  const [msg, setMsg] = useState<string | null>(null);

  async function load(p = page) {
    setPageLoading(true);
    try {
      const res = await api.get(`/api/v1/projects/?page=${p}&per_page=12`);
      const body = res.data;
      const list: Project[] = body?.data ?? body;
      const m = body?.meta ?? { page: p, per_page: 12, total: list.length, pages: 1 };
      setProjects(Array.isArray(list) ? list : []);
      setMeta(m);
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || "Failed to load projects");
    } finally {
      setPageLoading(false);
    }
  }
  useEffect(() => { load(page); }, [page]);

  const filtered = projects.filter((p) => p.name.toLowerCase().includes(q.toLowerCase()));

  async function create() {
    if (!name.trim() || name.trim().length < 2) { setMsg("Name must be at least 2 characters"); return; }
    if (name.trim().length > 255) { setMsg("Name too long"); return; }
    setLoading(true); setMsg(null);
    try {
      await api.post("/api/v1/projects/", { name: name.trim(), description: desc.trim() || undefined });
      setName(""); setDesc(""); setShowModal(false);
      await load(1); setPage(1);
      setMsg(null);
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || "Failed to create project");
    } finally { setLoading(false); }
  }

  if (pageLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--primary)]" />
        <span className="ml-2 text-sm text-[var(--muted-foreground)]">Loading projects...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2"><FolderKanban className="h-5 w-5 text-[var(--primary)]" /> Projects</h1>
          <p className="text-sm text-[var(--muted-foreground)]">Tenant isolated • {meta.total} total</p>
        </div>
        <Button onClick={() => setShowModal(true)}><Plus className="h-4 w-4 mr-1" /> New Project</Button>
      </div>

      <div className="flex gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-[var(--muted-foreground)]" />
          <Input placeholder="Search projects..." className="pl-9" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="text-xs text-[var(--muted-foreground)] self-center">Page {meta.page}/{meta.pages}</div>
      </div>

      {msg && <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded p-2">{msg}</p>}

      {filtered.length === 0 ? (
        <Card><CardContent className="p-8 text-center text-sm text-[var(--muted-foreground)]">No projects yet. Create your first targeted scope.</CardContent></Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {filtered.map((p) => (
            <Link key={p.id} href={`/dashboard/projects/${p.id}`}>
              <Card className="hover:border-[var(--primary)]/40 transition-colors cursor-pointer h-full">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base truncate">{p.name}</CardTitle>
                  <p className="text-xs text-[var(--muted-foreground)] truncate">{p.id}</p>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-[var(--muted-foreground)] line-clamp-2 h-10">{p.description || "No description — add scope to start"}</p>
                  <p className="text-xs text-[var(--muted-foreground)] mt-3">{new Date(p.created_at).toLocaleDateString()}</p>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}

      <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
        <table className="w-full text-sm">
          <thead className="bg-[var(--muted)]/50 text-xs text-[var(--muted-foreground)]">
            <tr><th className="text-left p-3">Name</th><th className="text-left p-3">Owner</th><th className="text-left p-3">Created</th><th className="text-right p-3">Action</th></tr>
          </thead>
          <tbody>
            {filtered.map((p) => (
              <tr key={p.id} className="border-t border-[var(--border)] hover:bg-[var(--muted)]/30">
                <td className="p-3 font-medium">{p.name}</td>
                <td className="p-3 text-xs truncate max-w-[120px]">{p.owner_id}</td>
                <td className="p-3 text-xs">{new Date(p.created_at).toLocaleDateString()}</td>
                <td className="p-3 text-right"><Link href={`/dashboard/projects/${p.id}`} className="text-[var(--primary)] hover:underline text-xs">View →</Link></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-center gap-2">
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}><ChevronLeft className="h-4 w-4" /> Prev</Button>
        <span className="text-sm text-[var(--muted-foreground)]">Page {meta.page} of {meta.pages}</span>
        <Button variant="outline" size="sm" disabled={page >= meta.pages} onClick={() => setPage((p) => p + 1)}>Next <ChevronRight className="h-4 w-4" /></Button>
      </div>

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setShowModal(false)}>
          <div onClick={(e) => e.stopPropagation()} className="w-full max-w-md">
            <Card>
              <CardHeader><CardTitle>Create Project</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2"><Label>Name *</Label><Input value={name} onChange={(e) => setName(e.target.value)} placeholder="My Pentest Scope" maxLength={255} disabled={loading} /></div>
                <div className="space-y-2"><Label>Description</Label><Input value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="Optional" disabled={loading} /></div>
                {msg && <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded p-2">{msg}</p>}
                <div className="flex gap-2 justify-end">
                  <Button variant="ghost" onClick={() => setShowModal(false)} disabled={loading}>Cancel</Button>
                  <Button onClick={create} disabled={loading}>{loading ? "Creating..." : "Create"}</Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}
