import Database from 'better-sqlite3'

/**
 * Creates a fresh in-memory SQLite database with the full TaskFlow schema.
 * Use this in tests to get an isolated DB instance per test/suite.
 */
export function createTestDb(): Database.Database {
  const db = new Database(':memory:')
  db.pragma('journal_mode = WAL')
  db.pragma('foreign_keys = ON')

  db.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL DEFAULT '',
      role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')),
      is_active INTEGER NOT NULL DEFAULT 1,
      pending_approval INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE categories (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      color TEXT NOT NULL DEFAULT '#64748b',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE tasks (
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

    CREATE TABLE task_tags (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      name TEXT NOT NULL,
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );

    CREATE TABLE attachments (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );

    CREATE TABLE platform_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE INDEX idx_tasks_user_id ON tasks(user_id);
    CREATE INDEX idx_tasks_status ON tasks(status);
    CREATE INDEX idx_tasks_category_id ON tasks(category_id);
    CREATE INDEX idx_tasks_created_at ON tasks(created_at);
    CREATE INDEX idx_categories_user_id ON categories(user_id);
    CREATE INDEX idx_task_tags_task_id ON task_tags(task_id);
    CREATE INDEX idx_attachments_task_id ON attachments(task_id);
  `)

  return db
}

/** Insert a test user and return its ID. */
export function seedUser(db: Database.Database, overrides: Partial<{
  id: string; username: string; email: string; role: string
}> = {}): string {
  const id = overrides.id ?? 'user-test-001'
  db.prepare(`
    INSERT INTO users (id, username, email, password_hash, display_name, role)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    id,
    overrides.username ?? 'testuser',
    overrides.email ?? 'test@example.com',
    '$2a$10$placeholder',
    'Test User',
    overrides.role ?? 'user',
  )
  return id
}

/** Insert a test category and return its ID. */
export function seedCategory(db: Database.Database, userId: string, overrides: Partial<{
  id: string; name: string; color: string
}> = {}): string {
  const id = overrides.id ?? 'cat-test-001'
  db.prepare('INSERT INTO categories (id, user_id, name, color) VALUES (?, ?, ?, ?)').run(
    id, userId, overrides.name ?? 'Test Category', overrides.color ?? '#3b82f6',
  )
  return id
}

/** Insert a test task and return its ID. */
export function seedTask(db: Database.Database, userId: string, overrides: Partial<{
  id: string; title: string; description: string; category_id: string | null
  status: string; progress: number; due_date: string | null
}> = {}): string {
  const id = overrides.id ?? 'task-test-001'
  db.prepare(`
    INSERT INTO tasks (id, user_id, title, description, category_id, status, progress, due_date)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    userId,
    overrides.title ?? 'Test Task',
    overrides.description ?? '',
    overrides.category_id ?? null,
    overrides.status ?? 'in_progress',
    overrides.progress ?? 0,
    overrides.due_date ?? null,
  )
  return id
}
