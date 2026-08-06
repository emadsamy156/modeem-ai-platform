import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  // Replit preview is served through a proxied iframe on a different origin.
  allowedDevOrigins: ["*"],
  outputFileTracingRoot: path.join(__dirname),
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
