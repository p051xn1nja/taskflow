#!/bin/sh
set -e

# Ensure data directories exist and are writable by nextjs user
mkdir -p /app/data/uploads
chown -R nextjs:nodejs /app/data

echo "TaskFlow entrypoint: environment ready"

# Drop privileges and run the command as nextjs
exec su-exec nextjs "$@"
