# TaskFlow

Modern task management platform built with Next.js 14, SQLite, and NextAuth.

## Stack

- **Framework**: Next.js 14 (App Router) + React 18 + TypeScript
- **Styling**: Tailwind CSS + Lucide React icons
- **Database**: SQLite via better-sqlite3 (`/data/taskflow.db`, auto-initialized)
- **Auth**: NextAuth.js v4 (credentials provider, JWT sessions, bcryptjs)
- **Validation**: Zod
- **Rich Editor**: TipTap (tables, images, colors, alignment, links, highlights)
- **Deployment**: Docker → GHCR (`ghcr.io/p051xn1nja/taskflow:latest`)

## Commands

- `npm run dev` — Start dev server
- `npm run build` — Production build (standalone output)
- `npm run start` — Start production server
- `npm test` — Run test suite (Vitest, single run)
- `npm run test:watch` — Run tests in watch mode

## Project Structure

```
src/
├── app/              # Next.js App Router
│   ├── (app)/        # Protected routes (tasks, board, notes, categories, tags, admin)
│   │   ├── page.tsx          # Task list view
│   │   ├── board/page.tsx    # Kanban board view
│   │   ├── notes/            # Notes list + note editor ([id])
│   │   ├── calendar/         # Calendar view (day/week/month/year)
│   │   ├── categories/       # Category management
│   │   ├── tags/             # Tag management (colors, CRUD)
│   │   ├── statuses/         # Status management (workflow stages)
│   │   └── admin/            # Admin panel (users, settings)
│   ├── login/        # Auth pages
│   ├── api/          # REST API endpoints
│   │   ├── tasks/            # Task CRUD + per-task endpoints
│   │   ├── categories/       # Category CRUD
│   │   ├── tags/             # Tag CRUD (master tag table)
│   │   ├── notes/            # Note CRUD
│   │   ├── statuses/         # Status CRUD (user-defined workflow stages)
│   │   ├── calendar/         # Calendar endpoint (tasks + notes by date range)
│   │   ├── uploads/          # Task file upload, download, delete
│   │   ├── note-uploads/     # Note file upload, download, delete
│   │   ├── editor-upload/    # Rich editor inline image upload + serve
│   │   ├── admin/            # Admin: users CRUD, platform settings
│   │   └── auth/             # NextAuth + initial setup
│   ├── icon.tsx      # 32x32 PNG favicon (generated at build time)
│   └── apple-icon.tsx # 180x180 Apple Touch icon (generated at build time)
├── components/       # React components + UI library
│   ├── TaskCard.tsx          # List view task card (read-only expanded view)
│   ├── TaskForm.tsx          # Edit/create modal (progress, files, tags with autocomplete)
│   ├── RichEditor.tsx        # TipTap rich HTML editor (tables, images, colors, alignment)
│   ├── FileUpload.tsx        # Legacy upload component (unused, superseded by TaskForm)
│   ├── Sidebar.tsx           # Navigation sidebar
│   └── Providers.tsx         # NextAuth session provider
├── lib/              # Core: db.ts (schema), auth.ts, helpers
└── types/            # TypeScript type definitions
data/                 # SQLite DB + uploads (gitignored, mounted volume)
tests/
├── helpers/          # test-db.ts: in-memory SQLite with schema + seed helpers
├── unit/             # Utils, types, DB schema/constraints
├── integration/      # Task/category CRUD, filters, Kanban mapping
└── build.test.ts     # TypeScript compilation, file/dep checks
```

## Database

Schema is defined inline in `src/lib/db.ts` and auto-creates on startup.
Tables: `users`, `categories`, `statuses`, `tasks`, `tags`, `task_tags`, `notes`, `note_tags`, `note_tasks`, `note_attachments`, `attachments`, `platform_settings`.
SQLite runs in WAL mode with foreign keys enabled.

### Statuses System

Task workflow stages are user-defined via the `statuses` table:
- `statuses` table: `(id, user_id, name, color, position, is_completed, is_default, created_at)`
- Each user gets 3 default statuses seeded on first access: "To Do" (default), "In Progress", "Completed" (is_completed=1)
- `tasks.status_id` references `statuses.id` — the legacy `tasks.status` column is kept in sync for backwards compat
- `is_completed` flag determines done behavior (strikethrough, progress=100, opacity)
- `is_default` marks which status new tasks get and where tasks go when their status is deleted
- `position` controls column order on the Board view
- Deleting a status reassigns all its tasks to the default status with progress=0

### Tags System

Tags are managed via a master `tags` table with `(id, user_id, name, color)`. Tags are shared between tasks and notes:
- `task_tags` junction: `(id, task_id, tag_id)` — links tags to tasks
- `note_tags` junction: `(id, note_id, tag_id)` — links tags to notes
- Migration from old free-form `task_tags.name` to master tag references is handled automatically in `db.ts`

### Notes System

Notes have their own content model alongside tasks:
- `notes` table: `(id, user_id, title, content, created_at, updated_at)` — content is HTML from the rich editor
- `note_tags`: Links notes to tags
- `note_tasks`: Links notes to tasks (many-to-many)
- `note_attachments`: File attachments for notes (same schema as `attachments`)

## Deployment

- **Domain**: `task.sidecloud.net`
- **Port**: 7776 → container 3000
- **Image**: `ghcr.io/p051xn1nja/taskflow:latest`
- **CI**: GitHub Actions builds and pushes to GHCR on push to `main` (`.github/workflows/docker-publish.yml`)
  - Actions: `actions/checkout@v5`, `docker/login-action@v4`, `docker/metadata-action@v6`, `docker/build-push-action@v6` (Node.js 24-compatible)
- **Volumes**: DB and uploads persist at `/var/www/vhosts/sidecloud.net/docker/taskflow/`
- **Deploy on server**: `docker compose pull && docker compose up -d`

## Environment Variables

- `NEXTAUTH_SECRET` — Session encryption key (**required in production**; a dev-only fallback is used in development)
- `NEXTAUTH_URL` — Public URL (`https://task.sidecloud.net`)
- `NODE_ENV` — `production` in Docker

> **Security**: Never commit real secrets. The repo uses a clearly-named dev-only fallback for `NEXTAUTH_SECRET`. Production deployments must set this env var to a unique random string.

## Views

- **Tasks** (`/`): List view with filters, search, pagination
  - Expanded card view is read-only (description, tags with colors, attachments with download)
  - Tag names displayed as colored badges on each task card
  - Progress bar displayed on each card; editing progress is done via the edit modal
- **Board** (`/board`): Kanban board with dynamic user-defined columns
  - Columns driven by the user's `statuses` table, ordered by `position`
  - Users can add, rename, reorder, and delete columns via `/statuses`
  - HTML5 native drag-and-drop (zero dependencies) with optimistic UI updates
  - Moving cards updates `status_id` and `progress` via `PATCH /api/tasks/:id`
  - Dragging to a completed-status column sets progress=100; to default sets progress=0
  - Tag names displayed as colored badges on kanban cards
- **Notes** (`/notes`): Card grid view with search, tag filters, pagination
  - Each card shows title, content preview (HTML stripped), tags, linked task count, attachment count
  - Click to open full note editor
- **Note Editor** (`/notes/:id`): Full-page rich editor with auto-save
  - TipTap rich HTML editor: bold, italic, underline, strikethrough, code, headings (H1-H3)
  - Text colors (12 presets), highlight colors, text alignment (left, center, right, justify)
  - Bullet lists, ordered lists, blockquotes, horizontal rules, code blocks
  - Tables: insert with configurable rows/cols, add/delete rows/columns, table settings modal (border width, border color, cell padding, width)
  - Images: upload via toolbar button, pasted/dropped images uploaded to `/api/editor-upload`
  - Links: add/remove with URL input
  - Tag management with autocomplete from master tags
  - Task linking: search and link/unlink tasks to notes
  - File attachments: upload (drag-and-drop or browse), download, delete — same limits as tasks
  - Auto-save with 2s debounce + manual save button
- **Calendar** (`/calendar`): Visual calendar view of tasks and notes
  - Four view modes: Day, Week, Month, Year — toggle via toolbar buttons
  - **Monthly**: Classic 7-column grid, items shown as colored pills, "+N more" overflow
  - **Weekly**: 7-column card layout with detailed items per day
  - **Daily**: Focused single-day view with items grouped by type (tasks, notes)
  - **Yearly**: 4x3 mini-month grid with activity dot indicators, click to drill into month
  - Tasks shown by `due_date`, notes shown by `created_at`
  - Filters: category, status, tag, content type (tasks/notes/both)
  - Navigation: prev/next arrows, "Today" quick button
  - Create menu: "New Task" (redirects to tasks page with pre-filled due date) or "New Note"
- **Statuses** (`/statuses`): Manage workflow stages for tasks
  - CRUD for statuses with color picker and "marks as completed" toggle
  - Drag-and-drop reordering (changes board column order)
  - Default status indicated with badge; cannot be deleted
  - Shows task count per status
- **Tags** (`/tags`): Dedicated tag management view
  - CRUD for tags with color picker (12 presets + custom hex)
  - Shows task and note usage counts per tag
  - Tags are shared across tasks and notes
- **Edit Modal** (`TaskForm`): Unified edit experience for both list and board views
  - Progress slider (edit mode only) — updates task progress directly
  - File attachments: upload (drag-and-drop or browse), download, and delete
  - Tags with autocomplete dropdown from master tags, colored badges
  - Category, due date, title, description editing
  - New files are staged and uploaded on save; attachment deletes are immediate
- **Admin Panel** (`/admin`): Admin-only dashboard
  - **Users** (`/admin/users`): Manage users — activate/deactivate, approve pending registrations, delete
  - **Settings** (`/admin/settings`): Platform-wide settings (registration, approval, limits)

## File Uploads

- **Limits**: Max 10 files per task/note, 50 MB total per task/note
- **Allowed extensions**:
  - Documents: pdf, txt, md, docx, doc, xlsx, xls, pptx, ppt, csv, json, rtf, odt
  - Archives: zip, rar, 7z, tar, gz
  - Images: png, jpg, jpeg, gif, webp, svg, bmp
- **Storage**: `/data/uploads/{id}.{ext}` with metadata in `attachments` / `note_attachments` tables
- **Upload**: Inline in edit modal/note editor with drag-and-drop zone; files staged before save
- **Management**: Download and delete individual attachments in edit mode
- **Task API**: `POST /api/uploads` (upload), `GET /api/uploads/:id` (download), `DELETE /api/uploads/:id` (delete)
- **Note API**: `POST /api/note-uploads` (upload), `GET /api/note-uploads/:id` (download), `DELETE /api/note-uploads/:id` (delete)
- **Editor Images**: `POST /api/editor-upload` (upload image, returns URL), `GET /api/editor-upload/:id` (serve image)

## Testing

- **Framework**: Vitest with in-memory SQLite (no external services needed)
- **Run before submitting**: `npm test` — 91 tests across 7 files, ~5s
- **Test DB helper**: `tests/helpers/test-db.ts` provides `createTestDb()`, `seedUser()`, `seedCategory()`, `seedTask()`, `seedStatuses()`
- **Coverage**: utilities, type contracts, schema constraints, foreign key cascades, CRUD operations, Kanban column mapping, build integrity
- **Adding tests**: Place unit tests in `tests/unit/`, integration tests in `tests/integration/`

## Favicon

- Generated at build time via Next.js `ImageResponse` (no static assets)
- `src/app/icon.tsx` — 32x32 PNG favicon (browser tabs)
- `src/app/apple-icon.tsx` — 180x180 Apple Touch icon (mobile bookmarks)
- Design: white checkmark on brand-blue gradient (`#1a75f5` → `#2a91ff`), rounded corners

## Platform Settings

Managed via Admin → Settings (`platform_settings` table):

- `app_name` — Display name for the app
- `max_tasks_per_user` — Max tasks per user (default: 1000)
- `max_file_size_mb` — Legacy per-file limit; total enforcement is 50 MB per task
- `max_categories_per_user` — Max categories per user (default: 50)
- `allow_registration` — Whether new users can self-register (default: false)
- `require_admin_approval` — New registrations require admin approval before activation (default: false)

## Key Conventions

- First registered user becomes admin
- API routes under `src/app/api/`
- Protected pages use the `(app)` route group
- Default limits: 1000 tasks, 50MB total uploads per task/note (10 files max), 50 categories per user
- Admin approval workflow: when enabled, new users get `pending_approval=true` until an admin activates them
- Tags are centrally managed with colors — shared between tasks and notes
- Statuses are user-defined workflow stages; default 3 seeded per user (To Do, In Progress, Completed)
- Board columns are dynamic — driven by statuses table, fully customizable
- Notes use HTML content via TipTap; editor images uploaded to `/api/editor-upload`
- Note-task linking allows associating notes with related tasks (many-to-many)
- Calendar view shows tasks (by due_date) and notes (by created_at) across day/week/month/year views
