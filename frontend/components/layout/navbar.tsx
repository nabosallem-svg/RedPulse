"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, LogOut, User } from "lucide-react";
import { clearAuth } from "@/lib/api";
import { Button } from "@/components/ui/button";

export function Navbar() {
  const router = useRouter();
  const [email, setEmail] = useState<string | null>(null);
  useEffect(() => {
    try {
      const raw = sessionStorage.getItem("rp_user");
      if (raw) setEmail(JSON.parse(raw)?.email ?? null);
      else {
        const ls = localStorage.getItem("rp_user");
        if (ls) setEmail(JSON.parse(ls)?.email ?? null);
      }
    } catch {}
  }, []);
  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-[var(--border)] bg-[var(--background)]/80 backdrop-blur px-4 md:px-6">
      <div className="flex items-center gap-2 md:hidden">
        <Shield className="h-5 w-5 text-[var(--primary)]" /> <span className="font-semibold">RedPulse</span>
      </div>
      <div className="hidden md:block text-sm text-[var(--muted-foreground)]">Controlled Pentesting â€¢ Targeted Scanning Only</div>
      <div className="flex items-center gap-3">
        <div className="hidden sm:flex items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--card)] px-3 py-1 text-sm">
          <User className="h-4 w-4 text-[var(--muted-foreground)]" /> <span className="max-w-[160px] truncate">{email ?? "User"}</span>
        </div>
        <Button variant="ghost" size="sm" onClick={() => { clearAuth(); router.push("/login"); }}>
          <LogOut className="h-4 w-4 mr-1" /> Logout
        </Button>
      </div>
    </header>
  );
}
