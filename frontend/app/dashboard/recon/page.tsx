"use client";
import { useEffect, useState, useCallback } from "react";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2, Search, AlertTriangle, CheckCircle2, XCircle, Clock, Globe, Server, RefreshCw } from "lucide-react";

interface ReconJob {
  id: string;
  engagement_id: string;
  tool: string;
  target: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  result_summary: Record<string, unknown> | null;
  created_at: string;
}

interface Asset {
  id: string;
  engagement_id: string;
  asset_type: string;
  value: string;
  port: number | null;
  protocol: string | null;
  service_name: string | null;
  technology: string | null;
  http_status: number | null;
  http_title: string | null;
  ip_address: string | null;
  source_tool: string;
  first_seen: string;
  last_seen: string;
}

interface Engagement {
  id: string;
  name: string;
  project_id: string;
  status: string;
}

export default function ReconPage() {
  const [jobs, setJobs] = useState<ReconJob[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toolStatus, setToolStatus] = useState<Record<string, boolean>>({});

  // Form state
  const [selectedEngagement, setSelectedEngagement] = useState("");
  const [target, setTarget] = useState("");
  const [tool, setTool] = useState("subfinder");

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [jobsRes, assetsRes, engRes, toolRes] = await Promise.all([
        api.get("/api/v1/recon/jobs").catch(() => ({ data: { data: [] } })),
        api.get("/api/v1/recon/assets").catch(() => ({ data: { data: [] } })),
        api.get("/api/v1/engagements/").catch(() => ({ data: { data: [] } })),
        api.get("/api/v1/recon/tools/status").catch(() => ({ data: { data: {} } })),
      ]);

      setJobs(Array.isArray(jobsRes.data?.data) ? jobsRes.data.data : []);
      setAssets(Array.isArray(assetsRes.data?.data) ? assetsRes.data.data : []);

      const engData = engRes.data?.data;
      setEngagements(Array.isArray(engData) ? engData : Array.isArray(engRes.data) ? engRes.data : []);

      const toolData = toolRes.data?.data;
      setToolStatus(toolData && typeof toolData === "object" ? toolData : {});
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to load recon data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const handleCreateJob = async () => {
    if (!selectedEngagement || !target.trim()) {
      setError("Select an engagement and enter a target");
      return;
    }
    setCreating(true);
    setError(null);
    try {
      await api.post("/api/v1/recon/jobs", {
        engagement_id: selectedEngagement,
        tool,
        target: target.trim(),
      });
      setTarget("");
      await loadData();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to create recon job");
    } finally {
      setCreating(false);
    }
  };

  const statusIcon = (status: string) => {
    switch (status) {
      case "completed": return <CheckCircle2 className="h-4 w-4 text-green-400" />;
      case "failed": return <XCircle className="h-4 w-4 text-red-400" />;
      case "running": return <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />;
      default: return <Clock className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const summary = (s: Record<string, unknown> | null) => {
    if (!s) return null;
    return (
      <span className="text-xs text-muted-foreground">
        {s.assets_found !== undefined ? `${s.assets_found} assets` : ""}
        {s.duration_seconds !== undefined ? ` in ${s.duration_seconds}s` : ""}
        {s.changes && s.changes !== "No changes detected" ? ` — ${s.changes}` : ""}
      </span>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--primary)]" />
        <span className="ml-2 text-sm text-muted-foreground">Loading recon...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Recon</h1>
        <p className="text-sm text-muted-foreground">Scope-enforced asset discovery — every target validated before execution</p>
      </div>

      {error && (
        <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded p-3">{error}</div>
      )}

      {/* Tool Status */}
      <div className="flex gap-3 flex-wrap">
        {Object.entries(toolStatus).map(([name, ok]) => (
          <div key={name} className="flex items-center gap-1.5 text-xs px-2 py-1 rounded border border-border">
            {ok ? <CheckCircle2 className="h-3 w-3 text-green-400" /> : <AlertTriangle className="h-3 w-3 text-amber-400" />}
            <span className="capitalize">{name}</span>
          </div>
        ))}
      </div>

      {/* Create Job Form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Search className="h-5 w-5" /> New Recon Job</CardTitle>
          <CardDescription>All targets are validated against scope rules before execution</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-4">
            <div>
              <Label className="text-xs">Engagement</Label>
              <select
                className="w-full mt-1 rounded-md border border-input bg-background px-3 py-2 text-sm"
                value={selectedEngagement}
                onChange={(e) => setSelectedEngagement(e.target.value)}
              >
                <option value="">Select engagement...</option>
                {engagements.map((eng) => (
                  <option key={eng.id} value={eng.id}>{eng.name}</option>
                ))}
              </select>
            </div>
            <div>
              <Label className="text-xs">Tool</Label>
              <select
                className="w-full mt-1 rounded-md border border-input bg-background px-3 py-2 text-sm"
                value={tool}
                onChange={(e) => setTool(e.target.value)}
              >
                <option value="subfinder">Subfinder (subdomains)</option>
                <option value="httpx">httpx (HTTP probe)</option>
                <option value="nmap">Nmap (port scan)</option>
              </select>
            </div>
            <div>
              <Label className="text-xs">Target</Label>
              <Input
                placeholder="example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="mt-1"
              />
            </div>
            <div className="flex items-end">
              <Button onClick={handleCreateJob} disabled={creating} className="w-full">
                {creating ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Search className="h-4 w-4 mr-2" />}
                Run Recon
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Jobs */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Jobs</CardTitle>
            <CardDescription>{jobs.length} total</CardDescription>
          </div>
          <Button variant="outline" size="sm" onClick={loadData}><RefreshCw className="h-4 w-4 mr-1" /> Refresh</Button>
        </CardHeader>
        <CardContent>
          {jobs.length === 0 ? (
            <p className="text-sm text-muted-foreground">No recon jobs yet. Create one above.</p>
          ) : (
            <div className="space-y-2 max-h-[400px] overflow-y-auto">
              {jobs.map((job) => (
                <div key={job.id} className="flex items-center gap-3 p-3 rounded border border-border bg-card/50 text-sm">
                  {statusIcon(job.status)}
                  <div className="flex-1 min-w-0">
                    <span className="font-mono text-xs">{job.target}</span>
                    <span className="ml-2 text-xs text-muted-foreground capitalize">{job.tool}</span>
                  </div>
                  {summary(job.result_summary)}
                  {job.error_message && (
                    <span className="text-xs text-red-400 truncate max-w-[200px]">{job.error_message}</span>
                  )}
                  <span className="text-xs text-muted-foreground whitespace-nowrap">
                    {new Date(job.created_at).toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Assets */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Globe className="h-5 w-5" /> Discovered Assets</CardTitle>
          <CardDescription>{assets.length} assets across all engagements</CardDescription>
        </CardHeader>
        <CardContent>
          {assets.length === 0 ? (
            <p className="text-sm text-muted-foreground">No assets discovered yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-xs text-muted-foreground border-b border-border">
                    <th className="text-left py-2 px-2">Value</th>
                    <th className="text-left py-2 px-2">Type</th>
                    <th className="text-left py-2 px-2">Port</th>
                    <th className="text-left py-2 px-2">Service</th>
                    <th className="text-left py-2 px-2">Tech</th>
                    <th className="text-left py-2 px-2">Source</th>
                    <th className="text-left py-2 px-2">Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map((a) => (
                    <tr key={a.id} className="border-b border-border/50 hover:bg-muted/30">
                      <td className="py-2 px-2 font-mono text-xs">{a.value}</td>
                      <td className="py-2 px-2 text-xs">{a.asset_type}</td>
                      <td className="py-2 px-2 text-xs">{a.port ?? "—"}</td>
                      <td className="py-2 px-2 text-xs">{a.service_name ?? "—"}</td>
                      <td className="py-2 px-2 text-xs truncate max-w-[150px]">{a.technology ?? "—"}</td>
                      <td className="py-2 px-2 text-xs capitalize">{a.source_tool}</td>
                      <td className="py-2 px-2 text-xs text-muted-foreground">{new Date(a.last_seen).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
