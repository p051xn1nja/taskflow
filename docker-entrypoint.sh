#!/bin/sh
set -e

# Ensure data directories exist
mkdir -p /app/data/uploads

# Run any initialization if needed
echo "TaskFlow entrypoint: environment ready"

exec "$@"
