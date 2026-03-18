import { describe, it, expect, beforeEach } from 'vitest'
import type Database from 'better-sqlite3'
import { createTestDb, seedUser, seedCategory, seedTask } from '../helpers/test-db'

let db: Database.Database

beforeEach(() => {
  db = createTestDb()
})

describe('Schema: tables exist', () => {
  const expectedTables = ['users', 'categories', 'tasks', 'task_tags', 'attachments', 'platform_settings']

  it.each(expectedTables)('table "%s" exists', (table) => {
    const row = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
    ).get(table) as { name: string } | undefined
    expect(row).toBeDefined()
    expect(row!.name).toBe(table)
  })
})

describe('Schema: indexes exist', () => {
  const expectedIndexes = [
    'idx_tasks_user_id',
    'idx_tasks_status',
    'idx_tasks_category_id',
    'idx_tasks_created_at',
    'idx_categories_user_id',
    'idx_task_tags_task_id',
    'idx_attachments_task_id',
  ]

  it.each(expectedIndexes)('index "%s" exists', (index) => {
    const row = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='index' AND name=?"
    ).get(index) as { name: string } | undefined
    expect(row).toBeDefined()
  })
})

describe('Schema: constraints', () => {
  it('rejects invalid task status', () => {
    const userId = seedUser(db)
    expect(() =>
      db.prepare(
        "INSERT INTO tasks (id, user_id, title, status) VALUES ('t1', ?, 'test', 'invalid')"
      ).run(userId)
    ).toThrow()
  })

  it('rejects progress below 0', () => {
    const userId = seedUser(db)
    expect(() =>
      db.prepare(
        "INSERT INTO tasks (id, user_id, title, progress) VALUES ('t1', ?, 'test', -1)"
      ).run(userId)
    ).toThrow()
  })

  it('rejects progress above 100', () => {
    const userId = seedUser(db)
    expect(() =>
      db.prepare(
        "INSERT INTO tasks (id, user_id, title, progress) VALUES ('t1', ?, 'test', 101)"
      ).run(userId)
    ).toThrow()
  })

  it('rejects invalid user role', () => {
    expect(() =>
      db.prepare(
        "INSERT INTO users (id, username, email, password_hash, role) VALUES ('u1', 'bad', 'bad@t.com', 'hash', 'superadmin')"
      ).run()
    ).toThrow()
  })

  it('enforces unique username', () => {
    seedUser(db, { id: 'u1', username: 'alice', email: 'a@t.com' })
    expect(() =>
      seedUser(db, { id: 'u2', username: 'alice', email: 'b@t.com' })
    ).toThrow()
  })

  it('enforces unique email', () => {
    seedUser(db, { id: 'u1', username: 'alice', email: 'same@t.com' })
    expect(() =>
      seedUser(db, { id: 'u2', username: 'bob', email: 'same@t.com' })
    ).toThrow()
  })

  it('allows valid status values', () => {
    const userId = seedUser(db)
    expect(() =>
      db.prepare(
        "INSERT INTO tasks (id, user_id, title, status) VALUES ('t1', ?, 'test', 'in_progress')"
      ).run(userId)
    ).not.toThrow()
    expect(() =>
      db.prepare(
        "INSERT INTO tasks (id, user_id, title, status) VALUES ('t2', ?, 'test2', 'completed')"
      ).run(userId)
    ).not.toThrow()
  })

  it('allows valid progress range 0-100', () => {
    const userId = seedUser(db)
    for (const p of [0, 1, 50, 99, 100]) {
      expect(() =>
        db.prepare(
          `INSERT INTO tasks (id, user_id, title, progress) VALUES ('tp${p}', ?, 'test', ?)`
        ).run(userId, p)
      ).not.toThrow()
    }
  })
})

describe('Schema: foreign keys', () => {
  it('cascades delete from user to tasks', () => {
    const userId = seedUser(db)
    seedTask(db, userId, { id: 't1' })
    seedTask(db, userId, { id: 't2' })

    db.prepare('DELETE FROM users WHERE id = ?').run(userId)

    const count = db.prepare('SELECT COUNT(*) as c FROM tasks WHERE user_id = ?').get(userId) as { c: number }
    expect(count.c).toBe(0)
  })

  it('cascades delete from user to categories', () => {
    const userId = seedUser(db)
    seedCategory(db, userId, { id: 'c1' })

    db.prepare('DELETE FROM users WHERE id = ?').run(userId)

    const count = db.prepare('SELECT COUNT(*) as c FROM categories').get() as { c: number }
    expect(count.c).toBe(0)
  })

  it('sets category_id to NULL when category is deleted', () => {
    const userId = seedUser(db)
    const catId = seedCategory(db, userId, { id: 'c1' })
    seedTask(db, userId, { id: 't1', category_id: catId })

    db.prepare('DELETE FROM categories WHERE id = ?').run(catId)

    const task = db.prepare('SELECT category_id FROM tasks WHERE id = ?').get('t1') as { category_id: string | null }
    expect(task.category_id).toBeNull()
  })

  it('cascades delete from task to tags', () => {
    const userId = seedUser(db)
    seedTask(db, userId, { id: 't1' })
    db.prepare("INSERT INTO task_tags (id, task_id, name) VALUES ('tt1', 't1', 'urgent')").run()
    db.prepare("INSERT INTO task_tags (id, task_id, name) VALUES ('tt2', 't1', 'bug')").run()

    db.prepare('DELETE FROM tasks WHERE id = ?').run('t1')

    const count = db.prepare("SELECT COUNT(*) as c FROM task_tags WHERE task_id = 't1'").get() as { c: number }
    expect(count.c).toBe(0)
  })

  it('cascades delete from task to attachments', () => {
    const userId = seedUser(db)
    seedTask(db, userId, { id: 't1' })
    db.prepare(
      "INSERT INTO attachments (id, task_id, filename, original_name, mime_type, size) VALUES ('a1', 't1', 'f.pdf', 'doc.pdf', 'application/pdf', 1024)"
    ).run()

    db.prepare('DELETE FROM tasks WHERE id = ?').run('t1')

    const count = db.prepare("SELECT COUNT(*) as c FROM attachments WHERE task_id = 't1'").get() as { c: number }
    expect(count.c).toBe(0)
  })
})

describe('Schema: defaults', () => {
  it('task defaults: status=in_progress, progress=0', () => {
    const userId = seedUser(db)
    db.prepare("INSERT INTO tasks (id, user_id, title) VALUES ('t1', ?, 'test')").run(userId)
    const task = db.prepare('SELECT status, progress, description FROM tasks WHERE id = ?').get('t1') as {
      status: string; progress: number; description: string
    }
    expect(task.status).toBe('in_progress')
    expect(task.progress).toBe(0)
    expect(task.description).toBe('')
  })

  it('user defaults: role=user, is_active=1', () => {
    db.prepare(
      "INSERT INTO users (id, username, email, password_hash) VALUES ('u1', 'joe', 'joe@t.com', 'hash')"
    ).run()
    const user = db.prepare('SELECT role, is_active FROM users WHERE id = ?').get('u1') as {
      role: string; is_active: number
    }
    expect(user.role).toBe('user')
    expect(user.is_active).toBe(1)
  })

  it('category defaults: color=#64748b', () => {
    const userId = seedUser(db)
    db.prepare("INSERT INTO categories (id, user_id, name) VALUES ('c1', ?, 'Test')").run(userId)
    const cat = db.prepare('SELECT color FROM categories WHERE id = ?').get('c1') as { color: string }
    expect(cat.color).toBe('#64748b')
  })
})
