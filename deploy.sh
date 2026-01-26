#!/usr/bin/env bash
set -euo pipefail

# deploy.sh - helper script to run migrations and give instructions for deploying to Render
# Usage: ./deploy.sh

if [ -z "${SUPABASE_DB_URL:-}" ]; then
  echo "SUPABASE_DB_URL not set. Set it in your environment (connection string to Postgres)."
  exit 1
fi

if [ ! -f supabase/migrations/001_init.sql ]; then
  echo "Migration file supabase/migrations/001_init.sql not found. Skipping SQL migration."
else
  echo "Running SQL migration against SUPABASE_DB_URL..."
  psql "$SUPABASE_DB_URL" -f supabase/migrations/001_init.sql
fi

echo "Done. To deploy on Render: push this repo to GitHub and create a Render Web Service using render.yaml or manual configuration."
