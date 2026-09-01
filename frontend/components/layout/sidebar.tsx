"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { LayoutDashboard, FolderKanban, Target, Settings, LogOut, Shield, FileText, Activity, Search, Bug, CreditCard, Users, Zap, Flag } from "lucide-react";
import { cn } from "@/lib/utils";
import { clearAuth } from "@/lib/api";

const topNav = [
  { href: "/dashboard/new-scan", label: "New Scan", icon: Zap, highlight: true },
];
const nav = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/dashboard/projects", label: "Projects", icon: FolderKanban },
  { href: "/dashboard/engagements", label: "Engagements", icon: Target },
  { href: "/dashboard/recon", label: "Recon", icon: Search },
  { href: "/dashboard/scans", label: "Scans", icon: Activity },
  { href: "/dashboard/triage", label: "Triage", icon: Flag },
  { href: "/dashboard/team", label: "Team", icon: Users },
  { href: "/dashboard/billing", label: "Billing", icon: CreditCard },
  { href: "/dashboard/reports", label: "Reports", icon: FileText },
  { href: "/dashboard/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  return (
    <aside className="hidden md:flex w-64 shrink-0 flex-col border-r border-[var(--border)] bg-[var(--card)]/50 backdrop-blur">
      <div className="flex h-16 items-center gap-2 border-b border-[var(--border)] px-6">
        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-[var(--primary)] text-white shadow-lg shadow-[rgba(255,30,39,0.3)]">
          <Activity className="h-5 w-5 animate-pulse" />
        </div>
        <span className="font-semibold tracking-tight neon-text">RedPulse</span>
        <span className="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-[var(--primary)]/20 text-[var(--primary)] border border-[var(--primary)]/30">SAAS</span>
      </div>
      <nav className="flex-1 space-y-1 p-3 overflow-y-auto">
        <div className="mb-3">
          {topNav.map((item) => {
            const active = pathname === item.href || pathname?.startsWith(item.href + "/");
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors border",
                  active ? "bg-[var(--primary)] text-white border-[var(--primary)] shadow-lg shadow-[rgba(255,30,39,0.3)]" : "bg-[var(--primary)]/10 text-[var(--primary)] border-[var(--primary)]/30 hover:bg-[var(--primary)] hover:text-white"
                )}
              >
                <item.icon className="h-4 w-4" />
                {item.label}
              </Link>
            );
          })}
        </div>
        <div className="h-px bg-[var(--border)] my-2" />
        {nav.map((item) => {
          const active = pathname === item.href || pathname?.startsWith(item.href + "/");
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                active ? "bg-[var(--primary)] text-[var(--primary-foreground)] shadow" : "text-[var(--muted-foreground)] hover:bg-[var(--muted)] hover:text-[var(--foreground)]"
              )}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="p-3 border-t border-[var(--border)]">
        <button
          onClick={() => { clearAuth(); router.push("/login"); }}
          className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-[var(--muted-foreground)] hover:bg-red-500/10 hover:text-red-400 transition-colors"
        >
          <LogOut className="h-4 w-4" /> Logout
        </button>
      </div>
    </aside>
  );
}
