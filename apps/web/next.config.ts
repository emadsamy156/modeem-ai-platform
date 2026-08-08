import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  // Replit preview is served through a proxied iframe on a different origin.
  allowedDevOrigins: [
    "*.replit.dev",
    "*.repl.co",
    "127.0.0.1",
    "localhost",
    ...(process.env.REPLIT_DEV_DOMAIN ? [process.env.REPLIT_DEV_DOMAIN] : []),
  ],
  outputFileTracingRoot: path.join(__dirname),
  async rewrites() {
    // Proxy API calls to the FastAPI backend so the browser stays same-origin
    // (required for HttpOnly session cookies behind the Replit preview proxy).
    // Note: the workspace proxy reserves /api/* for another service, so the
    // browser-facing prefix is /backend/*.
    const apiBase = process.env.API_INTERNAL_URL ?? "http://localhost:8000";
    return [{ source: "/backend/:path*", destination: `${apiBase}/:path*` }];
  },
  async headers() {
    if (process.env.NODE_ENV === "production") return [];
    // Prevent the Replit preview proxy/browser from caching stale responses in development.
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Cache-Control", value: "no-store, max-age=0" },
          { key: "Pragma", value: "no-cache" },
        ],
      },
    ];
  },
};

export default nextConfig;
