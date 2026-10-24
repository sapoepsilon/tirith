import type { NextConfig } from "next";

// REST and live events go through same-origin route handlers (src/app/tirith/*) that add the backend bearer
// token server side; there is no rewrite, so the browser never talks to the backend directly.
const nextConfig: NextConfig = {
  outputFileTracingRoot: __dirname,
  devIndicators: false,
};

export default nextConfig;
