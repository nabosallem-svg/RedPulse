"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import api, { setAuthToken } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield } from "lucide-react";

const schema = z.object({
  email: z.string().email(),
  password: z.string().min(8, "Password must be at least 8 characters"),
  full_name: z.string().optional(),
});
type Form = z.infer<typeof schema>;

export default function SignupPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { register, handleSubmit, formState: { errors } } = useForm<Form>({ resolver: zodResolver(schema) });

  async function onSubmit(data: Form) {
    setError(null); setLoading(true);
    try {
      const res = await api.post("/api/v1/auth/signup", { email: data.email, password: data.password, full_name: data.full_name });
      const { access_token, refresh_token } = (res.data as any) || {};
      if (access_token) setAuthToken(access_token, refresh_token, null);
      let user = null;
      try {
        const me = await api.get("/api/v1/auth/me");
        user = me.data;
      } catch {}
      setAuthToken(access_token, refresh_token, user ?? { email: data.email, full_name: data.full_name });
      router.push("/dashboard");
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Signup failed");
    } finally { setLoading(false); }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 grid-bg">
      <Card className="w-full max-w-md cyber-glow">
        <CardHeader className="text-center">
          <div className="mx-auto h-12 w-12 rounded-xl bg-[var(--primary)] flex items-center justify-center text-[var(--primary-foreground)] mb-2">
            <Shield className="h-6 w-6" />
          </div>
          <CardTitle>Create account</CardTitle>
          <CardDescription>Join RedPulse — Targeted Scanning Only</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label>Email</Label>
              <Input type="email" placeholder="you@company.com" {...register("email")} disabled={loading} />
              {errors.email && <p className="text-xs text-red-400">{errors.email.message}</p>}
            </div>
            <div className="space-y-2">
              <Label>Full name (optional)</Label>
              <Input placeholder="Ada Lovelace" {...register("full_name")} disabled={loading} />
            </div>
            <div className="space-y-2">
              <Label>Password</Label>
              <Input type="password" placeholder="min 8 characters" {...register("password")} disabled={loading} />
              {errors.password && <p className="text-xs text-red-400">{errors.password.message}</p>}
            </div>
            {error && <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded p-2">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading}>{loading ? "Creating..." : "Create account"}</Button>
            <p className="text-center text-sm text-[var(--muted-foreground)]">Already have an account? <Link href="/login" className="text-[var(--primary)] hover:underline">Sign in</Link></p>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
