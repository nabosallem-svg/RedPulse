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
  email: z.string().email("Invalid email"),
  password: z.string().min(1, "Password required"),
});
type Form = z.infer<typeof schema>;

export default function LoginPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { register, handleSubmit, formState: { errors } } = useForm<Form>({ resolver: zodResolver(schema) });

  async function onSubmit(data: Form) {
    setError(null); setLoading(true);
    try {
      const res = await api.post("/api/v1/auth/login", { email: data.email, password: data.password });
      const { access_token, token_type } = res.data;
      // fetch user profile
      let user = null;
      try {
        const me = await api.get("/api/v1/me", { headers: { Authorization: `Bearer ${access_token}` } });
        user = me.data;
      } catch {}
      setAuthToken(access_token, user ?? { email: data.email });
      router.push("/dashboard");
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Login failed. Check credentials.");
    } finally { setLoading(false); }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 grid-bg">
      <Card className="w-full max-w-md cyber-glow">
        <CardHeader className="text-center">
          <div className="mx-auto h-12 w-12 rounded-xl bg-[var(--primary)] flex items-center justify-center text-[var(--primary-foreground)] mb-2">
            <Shield className="h-6 w-6" />
          </div>
          <CardTitle className="text-2xl">Welcome back</CardTitle>
          <CardDescription>Sign in to RedPulse â€” Controlled Pentesting</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" placeholder="you@company.com" {...register("email")} />
              {errors.email && <p className="text-xs text-red-400">{errors.email.message}</p>}
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input id="password" type="password" placeholder="â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢" {...register("password")} />
              {errors.password && <p className="text-xs text-red-400">{errors.password.message}</p>}
            </div>
            {error && <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded p-2">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading}>{loading ? "Signing in..." : "Sign in"}</Button>
            <p className="text-center text-sm text-[var(--muted-foreground)]">No account? <Link href="/signup" className="text-[var(--primary)] hover:underline">Create one</Link></p>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
