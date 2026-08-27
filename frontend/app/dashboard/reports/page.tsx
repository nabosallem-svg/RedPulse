import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { FileText } from "lucide-react";
export default function ReportsPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold flex items-center gap-2"><FileText className="h-5 w-5 text-[var(--primary)]" /> Reports</h1>
      <Card><CardHeader><CardTitle>Professional Reports</CardTitle><CardDescription>Generate PDF/HTML from Findings + CVSS + Attack Path + Delta</CardDescription></CardHeader><CardContent className="text-sm text-[var(--muted-foreground)]">Use <code className="bg-[var(--muted)] px-1 rounded">POST /api/v1/projects/{"{id}"}/pentest/report?format=pdf</code> from the Findings dashboard to download the official PDF.</CardContent></Card>
    </div>
  );
}
