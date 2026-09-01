"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Users, Loader2, AlertTriangle, Trash2, Shield, UserPlus } from "lucide-react";

interface Workspace { id: string; name: string; slug: string; owner_id: string; }
interface Member { id: string; user_id: string; role: string; joined_at?: string; email?: string; }

export default function TeamPage() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [selectedWs, setSelectedWs] = useState("");
  const [members, setMembers] = useState<Member[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"admin" | "analyst" | "viewer">("viewer");
  const [inviting, setInviting] = useState(false);
  const [myRole, setMyRole] = useState<string | null>(null);

  useEffect(() => {
    async function loadWs() {
      try {
        const res = await api.get("/api/v1/workspaces");
        const data = res.data?.data ?? res.data ?? [];
        const list: Workspace[] = Array.isArray(data) ? data : [];
        setWorkspaces(list);
        if (list.length > 0) setSelectedWs(list[0].id);
        else setError("لا يوجد Workspace — أنشئ واحدًا أولاً");
      } catch (e: any) {
        setError(e?.response?.data?.detail || "Failed to load workspaces");
      } finally {
        setLoading(false);
      }
    }
    loadWs();
  }, []);

  useEffect(() => {
    if (!selectedWs) return;
    loadMembers();
  }, [selectedWs]);

  async function loadMembers() {
    setError(null);
    try {
      const [membersRes, wsRes] = await Promise.all([
        api.get(`/api/v1/workspaces/${selectedWs}/members`),
        api.get(`/api/v1/workspaces/${selectedWs}`).catch(() => null),
      ]);
      const mData = membersRes.data?.data ?? membersRes.data ?? [];
      setMembers(Array.isArray(mData) ? mData : []);
      if (wsRes?.data) {
        const wsData = wsRes.data?.data ?? wsRes.data;
        setMyRole(wsData?.your_role || null);
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to load members");
    }
  }

  async function handleInvite() {
    if (!inviteEmail.trim()) {
      setError("أدخل الإيميل");
      return;
    }
    setInviting(true); setError(null); setSuccess(null);
    try {
      const res = await api.post(`/api/v1/workspaces/${selectedWs}/members`, {
        email: inviteEmail.trim(),
        role: inviteRole,
      });
      setSuccess(`تمت دعوة ${inviteEmail} كـ ${inviteRole}`);
      setInviteEmail("");
      loadMembers();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "فشل الدعوة — تأكد أن الإيميل مسجل مسبقًا");
    } finally {
      setInviting(false);
    }
  }

  async function handleRemove(memberId: string) {
    if (!confirm("هل أنت متأكد من إزالة هذا العضو؟")) return;
    setError(null);
    try {
      await api.delete(`/api/v1/workspaces/${selectedWs}/members/${memberId}`);
      setSuccess("تمت إزالة العضو");
      loadMembers();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "فشل الإزالة — تحتاج صلاحية Admin");
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--primary)]" />
        <span className="ml-2 text-sm text-[var(--muted-foreground)]">Loading team...</span>
      </div>
    );
  }

  const isAdmin = myRole === "admin";

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2"><Users className="h-6 w-6 text-[var(--primary)]" /> Team — Workspace Members</h1>
        <p className="text-sm text-[var(--muted-foreground)]">أعضاء الـ Workspace الحاليين — مربوط بـ <code className="bg-[var(--muted)] px-1 rounded">WorkspaceService</code> حقيقي</p>
      </div>

      {workspaces.length > 1 && (
        <select className="rounded-md border border-[var(--border)] bg-[var(--background)] px-3 py-2 text-sm" value={selectedWs} onChange={e => setSelectedWs(e.target.value)}>
          {workspaces.map(w => <option key={w.id} value={w.id}>{w.name} ({w.slug})</option>)}
        </select>
      )}

      {error && <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded p-3 flex gap-2"><AlertTriangle className="h-4 w-4 shrink-0" />{error}</div>}
      {success && <div className="text-sm text-green-400 bg-green-500/10 border border-green-500/20 rounded p-3">{success}</div>}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Users className="h-5 w-5" /> الأعضاء ({members.length}) {myRole && <span className="text-xs px-2 py-1 rounded bg-[var(--primary)]/20 text-[var(--primary)] border border-[var(--primary)]/30">دورك: {myRole}</span>}</CardTitle>
          <CardDescription>من <code className="bg-[var(--muted)] px-1 rounded">GET /api/v1/workspaces/{`{id}`}/members</code></CardDescription>
        </CardHeader>
        <CardContent>
          {members.length === 0 ? (
            <p className="text-sm text-[var(--muted-foreground)]">لا يوجد أعضاء بعد.</p>
          ) : (
            <div className="space-y-2">
              {members.map((m) => (
                <div key={m.id} className="flex items-center gap-3 p-3 rounded border border-[var(--border)] bg-[var(--card)]/50">
                  <div className="h-8 w-8 rounded-full bg-[var(--primary)]/20 flex items-center justify-center text-xs font-medium text-[var(--primary)]">{m.user_id.slice(0,2).toUpperCase()}</div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-mono truncate">{m.user_id}</div>
                    <div className="text-xs text-[var(--muted-foreground)]">ID: {m.id.slice(0,8)} • joined {m.joined_at ? new Date(m.joined_at).toLocaleDateString() : "—"}</div>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded border font-medium ${m.role === "admin" ? "bg-red-500/20 border-red-500/30 text-red-300" : m.role === "analyst" ? "bg-blue-500/20 border-blue-500/30 text-blue-300" : "bg-[var(--muted)] border-[var(--border)] text-[var(--muted-foreground)]"}`}>{m.role}</span>
                  {isAdmin && (
                    <Button size="sm" variant="outline" className="h-7 border-red-500/20 hover:bg-red-500/10 hover:text-red-400" onClick={() => handleRemove(m.id)}>
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><UserPlus className="h-5 w-5 text-[var(--primary)]" /> دعوة عضو جديد</CardTitle>
          <CardDescription>ينادي <code className="bg-[var(--muted)] px-1 rounded">POST /api/v1/workspaces/{`{id}`}/members</code> — للـ Admin فقط</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {!isAdmin && myRole ? (
            <p className="text-sm text-amber-400">تحتاج دور Admin لدعوة أعضاء — دورك الحالي: {myRole}</p>
          ) : null}
          <div className="grid gap-3 md:grid-cols-3">
            <div className="md:col-span-2">
              <Label className="text-xs">Email</Label>
              <Input placeholder="colleague@company.com" value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} className="mt-1" disabled={!isAdmin && !!myRole} />
            </div>
            <div>
              <Label className="text-xs">الدور</Label>
              <select className="w-full mt-1 rounded-md border border-[var(--border)] bg-[var(--background)] px-3 py-2 text-sm" value={inviteRole} onChange={e => setInviteRole(e.target.value as any)} disabled={!isAdmin && !!myRole}>
                <option value="viewer">Viewer (قراءة فقط)</option>
                <option value="analyst">Analyst (تحليل + triage)</option>
                <option value="admin">Admin (كل الصلاحيات)</option>
              </select>
            </div>
          </div>
          <Button onClick={handleInvite} disabled={inviting || (!isAdmin && !!myRole)} className="bg-[var(--primary)]">
            {inviting ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <UserPlus className="h-4 w-4 mr-1" />}
            إرسال الدعوة
          </Button>
          <p className="text-xs text-[var(--muted-foreground)]">العضو المدعو يجب أن يكون مسجلاً مسبقًا في النظام — الـ API يتحقق من `WorkspaceService.invite_member` ويطبق RBAC.</p>
        </CardContent>
      </Card>
    </div>
  );
}
