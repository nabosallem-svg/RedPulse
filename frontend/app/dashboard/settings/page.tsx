import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Settings } from "lucide-react";
export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold flex items-center gap-2"><Settings className="h-5 w-5 text-[var(--primary)]" /> Settings</h1>
      <Card><CardHeader><CardTitle>Workspace</CardTitle><CardDescription>Manage API URL, theme, and notifications</CardDescription></CardHeader><CardContent className="text-sm text-[var(--muted-foreground)]">API: <code className="bg-[var(--muted)] px-1 rounded">{process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}</code> • Telegram bot is optional plugin (see <code>lib/api.ts</code>).</CardContent></Card>
    </div>
  );
}
