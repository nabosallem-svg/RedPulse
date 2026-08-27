import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Activity } from "lucide-react";
export default function ScansPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold flex items-center gap-2"><Activity className="h-5 w-5 text-[var(--primary)]" /> Scans</h1>
      <Card><CardHeader><CardTitle>Active Scans</CardTitle><CardDescription>Real-time scan progress — Idle, Scanning, Completed (see Engagements)</CardDescription></CardHeader><CardContent className="text-sm text-[var(--muted-foreground)]">Trigger scans from <code className="bg-[var(--muted)] px-1 rounded">/dashboard/projects/[id]/engagements</code> — status is shown per engagement.</CardContent></Card>
    </div>
  );
}
