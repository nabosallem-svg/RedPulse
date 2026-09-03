import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // output: standalone is for Docker only — Vercel handles its own output
  ...(process.env.VERCEL ? {} : { output: "standalone" as const }),
  poweredByHeader: false,
  reactStrictMode: true,
  typescript: { ignoreBuildErrors: true },
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
