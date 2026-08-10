# syntax=docker/dockerfile:1
#
# SurfaceWatch frontend (Next.js 14 App Router).
#
# Targets:
#   dev   — source bind-mounted, `next dev` with fast refresh
#   prod  — `next build` baked in, served by `next start`

FROM node:20-bookworm-slim AS base

ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /app

# Copied separately from the source so a source edit does not invalidate the
# dependency layer. `npm ci` rather than `npm install` — it installs exactly
# what package-lock.json pins and fails if the two have drifted.
COPY package.json package-lock.json ./
RUN npm ci

EXPOSE 3000


# --- dev --------------------------------------------------------------------
FROM base AS dev

# node:20 already provides an unprivileged `node` user (uid 1000). /app is
# root-owned from the COPY above, and `next dev` writes .next/ at runtime, so
# hand it over rather than running the dev server as root.
#
# .next must exist *in the image* before the named volume is mounted over it.
# Docker seeds an empty named volume from the image's contents at that path,
# ownership included; when the path is absent it creates the volume root-owned
# instead, and `next dev` running as node then fails with EACCES on its very
# first write. Creating it here is what makes the volume node-owned.
RUN mkdir -p /app/.next && chown -R node:node /app
USER node

CMD ["npm", "run", "dev"]


# --- build ------------------------------------------------------------------
FROM base AS build

COPY . .

# NEXT_PUBLIC_* values are inlined into the client bundle at build time, not
# read at runtime — so the production API URL has to be a build argument. A
# container started later with a different NEXT_PUBLIC_API_URL will still call
# whatever was baked in here.
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

RUN npm run build


# --- prod -------------------------------------------------------------------
FROM base AS prod

ENV NODE_ENV=production

COPY --from=build --chown=node:node /app/.next ./.next
COPY --from=build --chown=node:node /app/next.config.js ./
# There is no public/ directory in this app yet — no favicon, no static assets,
# and the empty states are inline SVG rather than files. Add
#   COPY --from=build --chown=node:node /app/public ./public
# here the moment one appears, or those assets will 404 in production only.

USER node
CMD ["npm", "run", "start"]
