"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { CreditCard, Loader2, AlertTriangle, CheckCircle2, Zap } from "lucide-react";

interface Workspace { id: string; name: string; slug: string; }

export default function BillingPage() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [selectedWs, setSelectedWs] = useState<string>("");
  const [subscription, setSubscription] = useState<any>(null);
  const [credits, setCredits] = useState<any>(null);
  const [plans, setPlans] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [checkoutLoading, setCheckoutLoading] = useState<string | null>(null);

  useEffect(() => {
    async function loadWorkspaces() {
      try {
        const res = await api.get("/api/v1/workspaces");
        const data = res.data?.data ?? res.data ?? [];
        const list: Workspace[] = Array.isArray(data) ? data : [];
        setWorkspaces(list);
        if (list.length > 0) setSelectedWs(list[0].id);
        else setError("No workspace found — create one from Team or via API POST /api/v1/workspaces");
      } catch (e: any) {
        setError(e?.response?.data?.detail || "Failed to load workspaces");
      } finally {
        setLoading(false);
      }
    }
    loadWorkspaces();
  }, []);

  useEffect(() => {
    if (!selectedWs) return;
    async function loadBilling() {
      setError(null);
      try {
        const [subRes, credRes, plansRes] = await Promise.all([
          api.get(`/api/v1/billing/${selectedWs}/subscription`).catch((e) => { throw e; }),
          api.get(`/api/v1/billing/${selectedWs}/credits`).catch(() => null),
          api.get(`/api/v1/billing/${selectedWs}/plans`).catch(() => null),
        ]);
        setSubscription(subRes.data?.data ?? subRes.data);
        if (credRes?.data) setCredits(credRes.data?.data ?? credRes.data);
        if (plansRes?.data) setPlans(plansRes.data?.data ?? plansRes.data);
      } catch (e: any) {
        const status = e?.response?.status;
        if (status === 404) {
          setError("No subscription found for this workspace — you are on Free plan by default.");
          // Still try to load plans
          try {
            const p = await api.get(`/api/v1/billing/${selectedWs}/plans`);
            setPlans(p.data?.data ?? p.data);
          } catch {}
        } else {
          setError(e?.response?.data?.detail || "Failed to load billing");
        }
      }
    }
    loadBilling();
  }, [selectedWs]);

  async function handleUpgrade(plan: string) {
    if (!selectedWs) return;
    setCheckoutLoading(plan);
    setError(null);
    try {
      const res = await api.post(`/api/v1/billing/${selectedWs}/checkout`, {
        plan,
        success_url: window.location.origin + "/dashboard/billing?success=1",
        cancel_url: window.location.origin + "/dashboard/billing?cancel=1",
      });
      const data = res.data?.data ?? res.data;
      const url = data?.url || data?.session_url;
      if (url) {
        window.location.href = url;
      } else {
        setError("Checkout session created but no URL returned: " + JSON.stringify(data).slice(0,200));
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Checkout failed — تأكد من إعداد Stripe keys في الباك إند");
    } finally {
      setCheckoutLoading(null);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--primary)]" />
        <span className="ml-2 text-sm text-[var(--muted-foreground)]">Loading billing...</span>
      </div>
    );
  }

  const planName = subscription?.plan || "free";
  const monthly = subscription?.credits?.monthly ?? subscription?.limits?.monthly_credits ?? credits?.monthly ?? 100;
  const used = subscription?.credits?.used ?? credits?.used ?? credits?.credits_used_this_period ?? 0;
  const remaining = subscription?.credits?.remaining ?? (monthly - used);
  const pct = monthly > 0 ? Math.min(100, Math.round((used / monthly) * 100)) : 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2"><CreditCard className="h-6 w-6 text-[var(--primary)]" /> Billing</h1>
        <p className="text-sm text-[var(--muted-foreground)]">الخطة الحالية واستهلاك Credits — مربوط بـ <code className="bg-[var(--muted)] px-1 rounded">BillingService</code> و <code className="bg-[var(--muted)] px-1 rounded">Stripe Checkout</code> الحقيقي</p>
      </div>

      {workspaces.length > 1 && (
        <select className="rounded-md border border-[var(--border)] bg-[var(--background)] px-3 py-2 text-sm" value={selectedWs} onChange={e => setSelectedWs(e.target.value)}>
          {workspaces.map(w => <option key={w.id} value={w.id}>{w.name} ({w.slug})</option>)}
        </select>
      )}

      {error && <div className="text-sm text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded p-3 flex gap-2"><AlertTriangle className="h-4 w-4 shrink-0" />{error}</div>}

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="border-[var(--primary)]/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Zap className="h-5 w-5 text-[var(--primary)]" /> الخطة الحالية</CardTitle>
            <CardDescription>من <code className="bg-[var(--muted)] px-1 rounded">GET /api/v1/billing/{`{ws}`}/subscription</code></CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center gap-3">
              <span className="text-2xl font-bold capitalize">{planName}</span>
              <span className={`text-xs px-2 py-1 rounded border ${subscription?.status === "active" ? "bg-green-500/10 border-green-500/20 text-green-300" : "bg-[var(--muted)] border-[var(--border)]"}`}>{subscription?.status || "active"}</span>
            </div>
            {subscription?.limits && (
              <div className="text-xs text-[var(--muted-foreground)] space-y-1">
                <div>Max Projects: {subscription.limits.max_projects} • Scans/day: {subscription.limits.max_scans_per_day}</div>
                <div>Price: ${subscription.limits.price_monthly || 0}/mo • Credits: {subscription.limits.monthly_credits}</div>
              </div>
            )}
            {!subscription && <p className="text-sm text-[var(--muted-foreground)]">Free plan — قم بالترقية للحصول على ميزات إضافية.</p>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>استهلاك Credits</CardTitle>
            <CardDescription>من <code className="bg-[var(--muted)] px-1 rounded">GET /api/v1/billing/{`{ws}`}/credits</code></CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex justify-between text-sm">
              <span>{used} مستخدم</span>
              <span>{remaining} متبقي من {monthly}</span>
            </div>
            <div className="h-3 rounded-full bg-[var(--muted)] overflow-hidden">
              <div className="h-full bg-[var(--primary)] transition-all" style={{ width: `${pct}%` }} />
            </div>
            <div className="text-xs text-[var(--muted-foreground)]">{pct}% مستهلك هذا الشهر {subscription?.current_period_end ? `• ينتهي ${new Date(subscription.current_period_end).toLocaleDateString()}` : ""}</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Upgrade Plan — Stripe Checkout حقيقي</CardTitle>
          <CardDescription>ينادي <code className="bg-[var(--muted)] px-1 rounded">POST /api/v1/billing/{`{ws}`}/checkout</code> ويفتح Stripe session</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {plans ? (
            <div className="grid gap-3 md:grid-cols-4">
              {Object.entries(plans).map(([key, p]: any) => {
                const isCurrent = key === planName;
                const metadata = p; // full metadata object now
                return (
                  <div key={key} className={`rounded border p-4 space-y-2 ${isCurrent ? "border-[var(--primary)] bg-[var(--primary)]/5" : "border-[var(--border)] bg-[var(--card)]"}`}>
                    <div className="font-semibold capitalize flex items-center gap-2">{metadata.name} {isCurrent && <span className="text-xs px-1.5 py-0.5 rounded bg-green-500/20 text-green-300 border border-green-500/20">حالي</span>}</div>
                    <div className="text-2xl font-bold">{metadata.price} {$}</div>
                    <div className="text-xs text-[var(--muted-foreground)]">{metadata.currency} {metadata.billing_interval}</div>
                    <div className="text-xs text-[var(--muted-foreground)]">(metadata.billing)</div>
                    <div className="text-xs text-[var(--muted-foreground)]">{metadata.description}</div>
                    <div className="text-xs text-[var(--muted-foreground)]">features: {metadata.features.join(", ")}</div>
                    {key !== "free" && (
                      <Button onClick={() => handleUpgrade(key)} disabled={!!checkoutLoading || isCurrent} className="w-full mt-2 bg-[var(--primary)]">
                        {checkoutLoading === key ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <CreditCard className="h-4 w-4 mr-1" />}
                        {isCurrent ? "الخطة الحالية" : "Upgrade Plan"}
                      </Button>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="text-sm text-[var(--muted-foreground)]">جاري تحميل الخطط...</p>
          )}
          <p className="text-xs text-[var(--muted-foreground)]">الضغط على Upgrade يفتح Stripe Checkout حقيقي (test mode) — الـ webhook يحدث الـ Subscription تلقائيًا.</p>
        </CardContent>
      </Card>
    </div>
  );
}
