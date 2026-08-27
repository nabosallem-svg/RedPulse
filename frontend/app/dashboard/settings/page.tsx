"use client";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Settings } from "lucide-react";

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold flex items-center gap-2"><Settings className="h-5 w-5 text-[var(--primary)]" /> Settings</h1>
      <Card>
        <CardHeader>
          <CardTitle>Workspace</CardTitle>
          <CardDescription>API connection and account information</CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-[var(--muted-foreground)] space-y-2">
          <p>API: <code className="bg-[var(--muted)] px-1 rounded">{typeof window !== "undefined" ? (window as any).__NEXT_DATA__?.props?.pageProps?.apiUrl || "Connected" : "Connected"}</code></p>
          <p>Auth: JWT with automatic token refresh</p>
        </CardContent>
      </Card>
    </div>
  );
}
