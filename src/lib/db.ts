import Database from 'better-sqlite3'
import path from 'path'
import fs from 'fs'

const DATA_DIR = path.join(process.cwd(), 'data')
const DB_PATH = path.join(DATA_DIR, 'taskflow.db')

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true })
}

const UPLOADS_DIR = path.join(DATA_DIR, 'uploads')
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true })
}

let _db: Database.Database | null = null

export function getDb(): Database.Database {
  if (!_db) {
    _db = new Database(DB_PATH)
    _db.pragma('journal_mode = WAL')
    _db.pragma('foreign_keys = ON')
    initializeSchema(_db)
  }
  return _db
}

function generateId(): string {
  return require('crypto').randomUUID().replace(/-/g, '').slice(0, 24)
}

/** Seed default statuses for a user if they have none. */
export function ensureDefaultStatuses(db: Database.Database, userId: string) {
  const count = db.prepare('SELECT COUNT(*) as c FROM statuses WHERE user_id = ?').get(userId) as { c: number }
  if (count.c > 0) return

  const defaults = [
    { name: 'To Do', color: '#64748b', position: 0, is_completed: 0, is_default: 1 },
    { name: 'In Progress', color: '#3b82f6', position: 1, is_completed: 0, is_default: 0 },
    { name: 'Completed', color: '#22c55e', position: 2, is_completed: 1, is_default: 0 },
  ]
  const stmt = db.prepare(
    'INSERT INTO statuses (id, user_id, name, color, position, is_completed, is_default) VALUES (?, ?, ?, ?, ?, ?, ?)'
  )
  for (const d of defaults) {
    stmt.run(generateId(), userId, d.name, d.color, d.position, d.is_completed, d.is_default)
  }
}

function initializeSchema(db: Database.Database) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL DEFAULT '',
      role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')),
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS categories (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      color TEXT NOT NULL DEFAULT '#64748b',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS statuses (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      color TEXT NOT NULL DEFAULT '#3b82f6',
      position INTEGER NOT NULL DEFAULT 0,
      is_completed INTEGER NOT NULL DEFAULT 0,
      is_default INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      category_id TEXT,
      status TEXT NOT NULL DEFAULT 'in_progress' CHECK(status IN ('in_progress', 'completed')),
      status_id TEXT,
      progress INTEGER NOT NULL DEFAULT 0 CHECK(progress >= 0 AND progress <= 100),
      due_date TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS tags (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      color TEXT NOT NULL DEFAULT '#3b82f6',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS attachments (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS platform_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS note_tags (
      id TEXT PRIMARY KEY,
      note_id TEXT NOT NULL,
      tag_id TEXT NOT NULL,
      FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
      FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS note_tasks (
      id TEXT PRIMARY KEY,
      note_id TEXT NOT NULL,
      task_id TEXT NOT NULL,
      FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS note_attachments (
      id TEXT PRIMARY KEY,
      note_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id);
    CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
    CREATE INDEX IF NOT EXISTS idx_tasks_category_id ON tasks(category_id);
    CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at);
    CREATE INDEX IF NOT EXISTS idx_categories_user_id ON categories(user_id);
    CREATE INDEX IF NOT EXISTS idx_attachments_task_id ON attachments(task_id);
    CREATE INDEX IF NOT EXISTS idx_tags_user_id ON tags(user_id);
    CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);
    CREATE INDEX IF NOT EXISTS idx_notes_created_at ON notes(created_at);
    CREATE INDEX IF NOT EXISTS idx_note_tags_note_id ON note_tags(note_id);
    CREATE INDEX IF NOT EXISTS idx_note_tags_tag_id ON note_tags(tag_id);
    CREATE INDEX IF NOT EXISTS idx_note_tasks_note_id ON note_tasks(note_id);
    CREATE INDEX IF NOT EXISTS idx_note_tasks_task_id ON note_tasks(task_id);
    CREATE INDEX IF NOT EXISTS idx_note_attachments_note_id ON note_attachments(note_id);
    CREATE INDEX IF NOT EXISTS idx_statuses_user_id ON statuses(user_id);
  `)

  // Migrations: add columns that may not exist yet
  const userColumns = db.prepare("PRAGMA table_info(users)").all() as { name: string }[]
  const userColumnNames = userColumns.map(c => c.name)
  if (!userColumnNames.includes('pending_approval')) {
    db.exec("ALTER TABLE users ADD COLUMN pending_approval INTEGER NOT NULL DEFAULT 0")
  }

  // Migration: add status_id to tasks if missing
  const taskColumns = db.prepare("PRAGMA table_info(tasks)").all() as { name: string }[]
  const taskColumnNames = taskColumns.map(c => c.name)
  if (!taskColumnNames.includes('status_id')) {
    db.exec("ALTER TABLE tasks ADD COLUMN status_id TEXT")
  }

  // Migration: add start_date to tasks if missing
  if (!taskColumnNames.includes('start_date')) {
    db.exec("ALTER TABLE tasks ADD COLUMN start_date TEXT")
  }

  // Migration: add board_position to tasks if missing (for kanban card ordering)
  if (!taskColumnNames.includes('board_position')) {
    db.exec("ALTER TABLE tasks ADD COLUMN board_position INTEGER NOT NULL DEFAULT 0")
  }

  // Migration: add location to tasks if missing
  if (!taskColumnNames.includes('location')) {
    db.exec("ALTER TABLE tasks ADD COLUMN location TEXT NOT NULL DEFAULT ''")
  }

  // Migration: task_tags old schema (name column) -> new schema (tag_id column)
  migrateTaskTags(db)

  // Migration: populate status_id for existing tasks
  migrateTaskStatuses(db)

  // Insert default platform settings if not exist
  const insertSetting = db.prepare(
    'INSERT OR IGNORE INTO platform_settings (key, value) VALUES (?, ?)'
  )
  insertSetting.run('app_name', 'TaskFlow')
  insertSetting.run('max_tasks_per_user', '1000')
  insertSetting.run('max_file_size_mb', '25')
  insertSetting.run('allow_registration', 'false')
  insertSetting.run('max_categories_per_user', '50')
  insertSetting.run('require_admin_approval', 'false')
}

function migrateTaskStatuses(db: Database.Database) {
  // For each user who has tasks but no statuses, seed defaults and assign
  const usersWithTasks = db.prepare(
    'SELECT DISTINCT user_id FROM tasks WHERE status_id IS NULL'
  ).all() as { user_id: string }[]

  for (const { user_id } of usersWithTasks) {
    ensureDefaultStatuses(db, user_id)

    const statuses = db.prepare(
      'SELECT id, name, is_completed, is_default, position FROM statuses WHERE user_id = ? ORDER BY position'
    ).all(user_id) as { id: string; name: string; is_completed: number; is_default: number; position: number }[]

    const todoStatus = statuses.find(s => s.is_default) || statuses[0]
    const inProgressStatus = statuses.find(s => !s.is_completed && !s.is_default && s.name === 'In Progress') || statuses.find(s => !s.is_completed && !s.is_default) || todoStatus
    const completedStatus = statuses.find(s => s.is_completed) || statuses[statuses.length - 1]

    // Map: in_progress+progress=0 → todo, in_progress+progress>0 → in_progress, completed → completed
    db.prepare(
      "UPDATE tasks SET status_id = ? WHERE user_id = ? AND status = 'in_progress' AND progress = 0 AND status_id IS NULL"
    ).run(todoStatus.id, user_id)

    db.prepare(
      "UPDATE tasks SET status_id = ? WHERE user_id = ? AND status = 'in_progress' AND progress > 0 AND status_id IS NULL"
    ).run(inProgressStatus.id, user_id)

    db.prepare(
      "UPDATE tasks SET status_id = ? WHERE user_id = ? AND status = 'completed' AND status_id IS NULL"
    ).run(completedStatus.id, user_id)
  }
}

function migrateTaskTags(db: Database.Database) {
  const taskTagsExists = db.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name='task_tags'"
  ).get()

  if (!taskTagsExists) {
    db.exec(`
      CREATE TABLE task_tags (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        tag_id TEXT NOT NULL,
        FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
        FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_task_tags_task_id ON task_tags(task_id);
      CREATE INDEX IF NOT EXISTS idx_task_tags_tag_id ON task_tags(tag_id);
    `)
    return
  }

  const ttColumns = db.prepare("PRAGMA table_info(task_tags)").all() as { name: string }[]
  const ttColumnNames = ttColumns.map(c => c.name)

  if (!ttColumnNames.includes('name')) {
    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_task_tags_task_id ON task_tags(task_id);
      CREATE INDEX IF NOT EXISTS idx_task_tags_tag_id ON task_tags(tag_id);
    `)
    return
  }

  // Old schema detected — migrate
  const existingTags = db.prepare(`
    SELECT DISTINCT tt.name, t.user_id
    FROM task_tags tt
    JOIN tasks t ON tt.task_id = t.id
  `).all() as { name: string; user_id: string }[]

  const insertTag = db.prepare('INSERT INTO tags (id, user_id, name, color) VALUES (?, ?, ?, ?)')
  const tagMap = new Map<string, string>()

  for (const { name, user_id } of existingTags) {
    const key = `${user_id}:${name}`
    if (!tagMap.has(key)) {
      const existing = db.prepare(
        'SELECT id FROM tags WHERE user_id = ? AND name = ?'
      ).get(user_id, name) as { id: string } | undefined

      if (existing) {
        tagMap.set(key, existing.id)
      } else {
        const tagId = generateId()
        insertTag.run(tagId, user_id, name, '#3b82f6')
        tagMap.set(key, tagId)
      }
    }
  }

  db.exec(`
    CREATE TABLE task_tags_new (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      tag_id TEXT NOT NULL,
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
    )
  `)

  const oldTags = db.prepare(`
    SELECT tt.id, tt.task_id, tt.name, t.user_id
    FROM task_tags tt
    JOIN tasks t ON tt.task_id = t.id
  `).all() as { id: string; task_id: string; name: string; user_id: string }[]

  const insertMap = db.prepare('INSERT INTO task_tags_new (id, task_id, tag_id) VALUES (?, ?, ?)')
  for (const { id, task_id, name, user_id } of oldTags) {
    const tagId = tagMap.get(`${user_id}:${name}`)
    if (tagId) insertMap.run(id, task_id, tagId)
  }

  db.exec('DROP TABLE task_tags')
  db.exec('ALTER TABLE task_tags_new RENAME TO task_tags')
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_task_tags_task_id ON task_tags(task_id);
    CREATE INDEX IF NOT EXISTS idx_task_tags_tag_id ON task_tags(tag_id);
  `)
}

export const UPLOADS_PATH = UPLOADS_DIR
