"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/layout/sidebar";
import { Navbar } from "@/components/layout/navbar";
import api from "@/lib/api";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [checked, setChecked] = useState(false);
  useEffect(() => {
    let cancelled = false;
    // httpOnly cookie check — try to fetch current user; if 401 fallback to login
    // Also allow dev preview without backend: if sessionStorage has user, allow
    const hasSessionUser = (() => {
      try { return !!sessionStorage.getItem("rp_user"); } catch { return false; }
    })();
    if (hasSessionUser) {
      setChecked(true);
      return;
    }
    api.get("/api/v1/auth/me").then(() => {
      if (!cancelled) setChecked(true);
    }).catch(() => {
      if (!cancelled) router.replace("/login");
    });
    return () => { cancelled = true; };
  }, [router]);
  if (!checked) {
    return <div className="min-h-screen flex items-center justify-center text-sm text-[var(--muted-foreground)]">Checking authentication...</div>;
  }
  return (
    <div className="min-h-screen flex bg-[var(--background)]">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <Navbar />
        <main className="flex-1 p-4 md:p-6 max-w-7xl w-full mx-auto">{children}</main>
      </div>
    </div>
  );
}
