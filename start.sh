#!/bin/sh
set -e

echo "Starting TaskFlow..."

# Run the Next.js standalone server
exec node server.js
