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

    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      category_id TEXT,
      status TEXT NOT NULL DEFAULT 'in_progress' CHECK(status IN ('in_progress', 'completed')),
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
  `)

  // Migrations: add columns that may not exist yet
  const userColumns = db.prepare("PRAGMA table_info(users)").all() as { name: string }[]
  const userColumnNames = userColumns.map(c => c.name)
  if (!userColumnNames.includes('pending_approval')) {
    db.exec("ALTER TABLE users ADD COLUMN pending_approval INTEGER NOT NULL DEFAULT 0")
  }

  // Migration: task_tags old schema (name column) -> new schema (tag_id column)
  migrateTaskTags(db)

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

function migrateTaskTags(db: Database.Database) {
  // Check if task_tags table exists
  const taskTagsExists = db.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name='task_tags'"
  ).get()

  if (!taskTagsExists) {
    // Fresh install: create with new schema
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

  // Check if task_tags has old schema (name column)
  const ttColumns = db.prepare("PRAGMA table_info(task_tags)").all() as { name: string }[]
  const ttColumnNames = ttColumns.map(c => c.name)

  if (!ttColumnNames.includes('name')) {
    // Already new schema
    // Ensure indexes exist
    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_task_tags_task_id ON task_tags(task_id);
      CREATE INDEX IF NOT EXISTS idx_task_tags_tag_id ON task_tags(tag_id);
    `)
    return
  }

  // Old schema detected — migrate
  // 1. Extract unique (user_id, tag_name) pairs
  const existingTags = db.prepare(`
    SELECT DISTINCT tt.name, t.user_id
    FROM task_tags tt
    JOIN tasks t ON tt.task_id = t.id
  `).all() as { name: string; user_id: string }[]

  // 2. Insert into tags master table
  const insertTag = db.prepare('INSERT INTO tags (id, user_id, name, color) VALUES (?, ?, ?, ?)')
  const tagMap = new Map<string, string>() // "userId:name" -> tagId

  for (const { name, user_id } of existingTags) {
    const key = `${user_id}:${name}`
    if (!tagMap.has(key)) {
      // Check if tag already exists in master table
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

  // 3. Create new junction table
  db.exec(`
    CREATE TABLE task_tags_new (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      tag_id TEXT NOT NULL,
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
    )
  `)

  // 4. Migrate data
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

  // 5. Replace old table
  db.exec('DROP TABLE task_tags')
  db.exec('ALTER TABLE task_tags_new RENAME TO task_tags')
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_task_tags_task_id ON task_tags(task_id);
    CREATE INDEX IF NOT EXISTS idx_task_tags_tag_id ON task_tags(tag_id);
  `)
}

export const UPLOADS_PATH = UPLOADS_DIR
