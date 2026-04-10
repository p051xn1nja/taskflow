# TaskFlow v2.0

Modern task management platform built with Next.js, React, TypeScript, and SQLite.

## Tech Stack

- **Framework**: Next.js 14 (App Router) + TypeScript
- **UI**: Tailwind CSS with custom design system
- **Database**: SQLite via better-sqlite3
- **Auth**: NextAuth.js with credentials provider + bcrypt
- **Icons**: Lucide React
- **Deployment**: Docker container

## Features

- Task CRUD with title, description, categories, tags, due dates
- Adjustable per-task progress tracking (0-100%)
- File attachments (up to 10 per task, 25MB each)
- Category management with custom colors
- Search, filter by category/status/date/tags
- Day-based grouping with collapsible sections
- Pagination
- Role-based access (admin/user)
- Admin panel: user management, platform settings
- First registered user becomes admin
- Beautiful dark theme with glassmorphism effects

## Getting Started

### Local Development

```bash
npm install
npm run dev
```

Open http://localhost:3000 - the first user you create becomes the admin.

### Docker Deployment

```bash
docker compose up -d --build
```

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `NEXTAUTH_SECRET` | JWT signing secret (required) | — |
| `NEXTAUTH_URL` | Base URL of the app | `http://localhost:3000` |
| `REMINDER_WEBHOOK_URL` | Optional webhook for reminder notifications (`/api/tasks/reminders?notify=1`) | — |

### Reminders API Notes

- `GET /api/tasks/reminders` supports:
  - `limit` (default `5`, max `20`) for row lists
  - `include_items=0|false` for counts-only responses
  - `notify=1|true` to trigger optional webhook dispatch (requires `REMINDER_WEBHOOK_URL`)
- response `meta` includes:
  - `notification_attempted` (`true` when `notify=1|true` is requested)
  - `notification_dispatched` (`true` only when webhook POST succeeds)
  - `notification_available` (`true` when `REMINDER_WEBHOOK_URL` is configured)
  - `notification_reason` (`not_requested`, `dispatched`, `no_webhook_configured`, `no_pending_reminders`, `webhook_failed`)

## Project Structure

```
src/
  app/
    (app)/           # Authenticated app routes
      page.tsx       # Tasks page
      categories/    # Category management
      admin/         # Admin panel (dashboard, users, settings)
    login/           # Login/setup page
    api/             # API routes (tasks, categories, uploads, admin)
  components/        # React components
  lib/               # Database, auth, utilities
  types/             # TypeScript types
data/                # SQLite database + uploads (gitignored)
```
