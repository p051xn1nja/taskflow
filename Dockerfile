FROM node:22-alpine AS base

# Install dependencies for better-sqlite3 native compilation
RUN apk add --no-cache python3 make g++

FROM base AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app

# Native deps for better-sqlite3 at runtime + su-exec for entrypoint privilege drop
RUN apk add --no-cache python3 make g++ su-exec

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy built application
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# Copy entrypoint and start scripts
COPY --chown=nextjs:nodejs docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY --chown=nextjs:nodejs start.sh ./start.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh ./start.sh

# Create data directory for SQLite + uploads
RUN mkdir -p /app/data/uploads && chown -R nextjs:nodejs /app/data

VOLUME /app/data

EXPOSE 3000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["./start.sh"]
