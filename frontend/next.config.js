/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Proxies /api/* to the backend in local dev so the browser only ever
  // talks to one origin — avoids CORS entirely for the common case, while
  // NEXT_PUBLIC_API_URL (see src/lib/api.ts) remains configurable for
  // deployments where the backend lives on a different host.
  async rewrites() {
    const backendUrl = process.env.NEXT_PUBLIC_API_URL || "http://backend:8000";
    return [{ source: "/api/:path*", destination: `${backendUrl}/api/:path*` }];
  },
};

module.exports = nextConfig;
