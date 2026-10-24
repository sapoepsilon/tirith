# Tirith dashboard (Next.js production build, :3000). Build context: ../dashboard
# NEXT_PUBLIC_* values are inlined at build time; change them in tirith.env and rebuild.
# Backend URL, API token and basic-auth credentials are runtime env (server side only), never build args.
FROM node:22.23.4-bookworm-slim AS build
RUN corepack enable
WORKDIR /src
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
ARG NEXT_PUBLIC_TIRITH_MOCK=
ENV NEXT_PUBLIC_TIRITH_MOCK=$NEXT_PUBLIC_TIRITH_MOCK \
    NEXT_TELEMETRY_DISABLED=1
# Keep devDependencies: `next start` needs typescript to load next.config.ts.
RUN pnpm build

FROM node:22.23.4-bookworm-slim
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
WORKDIR /app
COPY --from=build /src/package.json ./
COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/.next ./.next
COPY --from=build /src/public ./public
COPY --from=build /src/next.config.ts ./
EXPOSE 3000
# favicon.ico is outside the basic-auth middleware matcher, so it answers 200 without credentials.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD node -e "fetch('http://127.0.0.1:3000/favicon.ico').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
USER node
CMD ["node_modules/.bin/next", "start", "-H", "0.0.0.0", "-p", "3000"]
