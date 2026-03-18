# TaskFlow

Modern task management platform built with Next.js 14, SQLite, and NextAuth.

## Stack

- **Framework**: Next.js 14 (App Router) + React 18 + TypeScript
- **Styling**: Tailwind CSS + Lucide React icons
- **Database**: SQLite via better-sqlite3 (`/data/taskflow.db`, auto-initialized)
- **Auth**: NextAuth.js v4 (credentials provider, JWT sessions, bcryptjs)
- **Validation**: Zod
- **Deployment**: Docker → GHCR (`ghcr.io/p051xn1nja/taskflow:latest`)

## Commands

- `npm run dev` — Start dev server
- `npm run build` — Production build (standalone output)
- `npm run start` — Start production server

## Project Structure

```
src/
├── app/              # Next.js App Router
│   ├── (app)/        # Protected routes (tasks, board, categories, admin)
│   ├── login/        # Auth pages
│   └── api/          # REST API endpoints
├── components/       # React components + UI library
├── lib/              # Core: db.ts (schema), auth.ts, helpers
└── types/            # TypeScript type definitions
data/                 # SQLite DB + uploads (gitignored, mounted volume)
```

## Database

Schema is defined inline in `src/lib/db.ts` and auto-creates on startup.
Tables: `users`, `categories`, `tasks`, `task_tags`, `attachments`, `platform_settings`.
SQLite runs in WAL mode with foreign keys enabled.

## Deployment

- **Domain**: `task.sidecloud.net`
- **Port**: 7776 → container 3000
- **Image**: `ghcr.io/p051xn1nja/taskflow:latest`
- **CI**: GitHub Actions builds and pushes to GHCR on push to `main` (`.github/workflows/docker-publish.yml`)
- **Volumes**: DB and uploads persist at `/var/www/vhosts/sidecloud.net/docker/taskflow/`
- **Deploy on server**: `docker compose pull && docker compose up -d`

## Environment Variables

- `NEXTAUTH_SECRET` — Session encryption key (required, change from default)
- `NEXTAUTH_URL` — Public URL (`https://task.sidecloud.net`)
- `NODE_ENV` — `production` in Docker

## Views

- **Tasks** (`/`): List view with filters, search, pagination
- **Board** (`/board`): Kanban board with three columns (To Do, In Progress, Done)
  - Columns derived from task `status` and `progress` fields — no extra schema
  - To Do: `status='in_progress'` + `progress=0`; In Progress: `progress 1-99%`; Done: `status='completed'`
  - HTML5 native drag-and-drop (zero dependencies) with optimistic UI updates
  - Moving cards updates `status` and `progress` via `PATCH /api/tasks/:id`

## Key Conventions

- First registered user becomes admin
- API routes under `src/app/api/`
- Protected pages use the `(app)` route group
- Default limits: 1000 tasks, 25MB uploads, 50 categories per user
