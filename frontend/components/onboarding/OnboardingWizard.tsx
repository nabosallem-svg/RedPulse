"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import api from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { CheckCircle2, Circle, ArrowRight, Shield, Target, FileText, RefreshCw, Sparkles, BookOpen, Loader2, ExternalLink } from "lucide-react";

type Step = {
  id: string;
  title: string;
  description: string;
  docs: string;
  done: boolean;
  status: string;
  action?: { label: string; href: string };
};

export default function OnboardingWizard() {
  const [steps, setSteps] = useState<Step[]>([]);
  const [progress, setProgress] = useState({ done: 0, total: 8, percent: 0 });
  const [nextStep, setNextStep] = useState<Step | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get("/api/v1/onboarding/progress");
      const data = res.data?.data ?? res.data;
      setSteps(data.steps ?? []);
      setProgress(data.progress ?? { done: 0, total: 8, percent: 0 });
      setNextStep(data.next_step ?? null);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to load onboarding progress. Are you logged in?");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--primary)]" />
        <span className="ml-2 text-sm text-[var(--muted-foreground)]">Loading your first-run progress...</span>
      </div>
    );
  }

  if (error) {
    return (
      <Card className="border-red-500/20">
        <CardHeader>
          <CardTitle className="text-red-400">Could not load onboarding</CardTitle>
          <CardDescription>{error}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button onClick={load} variant="outline"><RefreshCw className="h-4 w-4 mr-2" />Retry</Button>
          <Link href="/login" className="ml-3"><Button>Go to login</Button></Link>
        </CardContent>
      </Card>
    );
  }

  const ICONS: Record<string, any> = {
    account: Shield,
    project: FileText,
    engagement: Target,
    authorization: Shield,
    scope: Target,
    first_scan: Sparkles,
    triage: CheckCircle2,
    retest_export: RefreshCw,
  };

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Sparkles className="h-6 w-6 text-[var(--primary)]" /> Welcome to REDPULSE — First Run
        </h1>
        <p className="text-sm text-[var(--muted-foreground)] mt-1">
          Controlled pentesting in ~5 minutes. Every target is validated via <code className="px-1 py-0.5 bg-[var(--muted)] rounded text-xs">scope_validator.validate_target</code> before execution.
        </p>
        <p className="text-xs text-[var(--muted-foreground)] mt-1" dir="rtl">
          تجربة أول استخدام: أنشئ مشروعاً → ثبّت التفويض → حدد النطاق → شغّل الفحص → راجع النتائج → أعد الاختبار وصدّر.
        </p>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center justify-between">
            <span>Progress — {progress.done}/{progress.total} steps</span>
            <span className="text-sm font-normal text-[var(--muted-foreground)]">{progress.percent}%</span>
          </CardTitle>
          <CardDescription>
            {nextStep ? (
              <>Next: <span className="font-medium text-[var(--foreground)]">{nextStep.title}</span> — {nextStep.description}</>
            ) : (
              <>All done — you’ve completed the first-run flow. Launch your next engagement from the dashboard.</>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-2 w-full bg-[var(--muted)] rounded-full overflow-hidden">
            <div className="h-full bg-[var(--primary)] transition-all" style={{ width: `${progress.percent}%` }} />
          </div>
        </CardContent>
      </Card>

      <div className="space-y-3">
        {steps.map((s) => {
          const Icon = ICONS[s.id] || Circle;
          const done = s.done;
          return (
            <Card key={s.id} className={done ? "border-green-500/20 bg-green-500/[0.03]" : ""}>
              <CardContent className="p-4 flex items-start gap-4">
                <div className={`mt-1 rounded-full p-1 ${done ? "bg-green-500/20 text-green-400" : "bg-[var(--muted)] text-[var(--muted-foreground)]"}`}>
                  {done ? <CheckCircle2 className="h-5 w-5" /> : <Icon className="h-5 w-5" />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`font-medium text-sm ${done ? "text-green-400" : ""}`}>{s.title}</span>
                    {done && <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/20 text-green-400">Done</span>}
                  </div>
                  <p className="text-xs text-[var(--muted-foreground)] mt-1">{s.description}</p>
                  <a href={s.docs} target="_blank" rel="noreferrer" className="text-xs text-[var(--primary)] hover:underline inline-flex items-center gap-1 mt-2">
                    <BookOpen className="h-3 w-3" /> Docs
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
                <div className="ml-2 shrink-0">
                  {done ? (
                    <span className="text-xs text-green-400 flex items-center gap-1"><CheckCircle2 className="h-3 w-3" /> Completed</span>
                  ) : s.action ? (
                    <Link href={s.action.href}>
                      <Button size="sm" variant={s.id === nextStep?.id ? "default" : "outline"}>
                        {s.action.label} <ArrowRight className="h-3 w-3 ml-1" />
                      </Button>
                    </Link>
                  ) : null}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Card className="border-[var(--primary)]/20 bg-[var(--primary)]/5">
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2"><BookOpen className="h-4 w-4" /> What’s next?</CardTitle>
          <CardDescription className="text-xs">
            Read <code>docs/ONBOARDING.md</code> for curl examples and <code>docs/pentest/INTERNAL_PENTEST_REPORT.md</code> for the pre-launch pentest that cleared this build. Legal: <Link href="/api/v1/legal/terms" className="text-[var(--primary)] hover:underline">Terms</Link> · <Link href="/api/v1/legal/privacy" className="text-[var(--primary)] hover:underline">Privacy</Link>.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Link href="/dashboard"><Button size="sm">Go to Dashboard</Button></Link>
          <a href="/docs/ONBOARDING.md" target="_blank"><Button size="sm" variant="outline">Open onboarding guide <ExternalLink className="h-3 w-3 ml-1" /></Button></a>
          <Button size="sm" variant="ghost" onClick={load}><RefreshCw className="h-3 w-3 mr-1" /> Refresh progress</Button>
        </CardContent>
      </Card>
    </div>
  );
}
