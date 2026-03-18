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

    CREATE TABLE statuses (
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

    CREATE TABLE tasks (
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

    CREATE TABLE tags (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      color TEXT NOT NULL DEFAULT '#3b82f6',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE task_tags (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      tag_id TEXT NOT NULL,
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
      FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
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

    CREATE TABLE notes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE note_tags (
      id TEXT PRIMARY KEY,
      note_id TEXT NOT NULL,
      tag_id TEXT NOT NULL,
      FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
      FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
    );

    CREATE TABLE note_tasks (
      id TEXT PRIMARY KEY,
      note_id TEXT NOT NULL,
      task_id TEXT NOT NULL,
      FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );

    CREATE TABLE note_attachments (
      id TEXT PRIMARY KEY,
      note_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE
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
    CREATE INDEX idx_task_tags_tag_id ON task_tags(tag_id);
    CREATE INDEX idx_attachments_task_id ON attachments(task_id);
    CREATE INDEX idx_tags_user_id ON tags(user_id);
    CREATE INDEX idx_statuses_user_id ON statuses(user_id);
    CREATE INDEX idx_notes_user_id ON notes(user_id);
    CREATE INDEX idx_notes_created_at ON notes(created_at);
    CREATE INDEX idx_note_tags_note_id ON note_tags(note_id);
    CREATE INDEX idx_note_tags_tag_id ON note_tags(tag_id);
    CREATE INDEX idx_note_tasks_note_id ON note_tasks(note_id);
    CREATE INDEX idx_note_tasks_task_id ON note_tasks(task_id);
    CREATE INDEX idx_note_attachments_note_id ON note_attachments(note_id);
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
  status: string; progress: number; due_date: string | null; status_id: string | null
}> = {}): string {
  const id = overrides.id ?? 'task-test-001'
  db.prepare(`
    INSERT INTO tasks (id, user_id, title, description, category_id, status, progress, due_date, status_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    userId,
    overrides.title ?? 'Test Task',
    overrides.description ?? '',
    overrides.category_id ?? null,
    overrides.status ?? 'in_progress',
    overrides.progress ?? 0,
    overrides.due_date ?? null,
    overrides.status_id ?? null,
  )
  return id
}

/** Insert default statuses for a user and return their IDs. */
export function seedStatuses(db: Database.Database, userId: string): { todoId: string; inProgressId: string; completedId: string } {
  const todoId = 'status-todo-001'
  const inProgressId = 'status-ip-001'
  const completedId = 'status-done-001'

  db.prepare('INSERT INTO statuses (id, user_id, name, color, position, is_completed, is_default) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    todoId, userId, 'To Do', '#64748b', 0, 0, 1
  )
  db.prepare('INSERT INTO statuses (id, user_id, name, color, position, is_completed, is_default) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    inProgressId, userId, 'In Progress', '#3b82f6', 1, 0, 0
  )
  db.prepare('INSERT INTO statuses (id, user_id, name, color, position, is_completed, is_default) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    completedId, userId, 'Completed', '#22c55e', 2, 1, 0
  )

  return { todoId, inProgressId, completedId }
}
