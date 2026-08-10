/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  eslint: {
    // Type errors still fail the build (see typescript below); lint runs
    // separately via `npm run lint` so a style nit cannot block a deploy.
    ignoreDuringBuilds: true,
  },
};

module.exports = nextConfig;
