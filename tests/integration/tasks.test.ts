import { describe, it, expect, beforeEach } from 'vitest'
import type Database from 'better-sqlite3'
import { createTestDb, seedUser, seedCategory, seedTask } from '../helpers/test-db'

/**
 * Integration tests that exercise task CRUD operations through the database
 * layer, mirroring what the API routes do. These catch regressions in query
 * logic without needing HTTP mocks.
 */

let db: Database.Database
let userId: string

beforeEach(() => {
  db = createTestDb()
  userId = seedUser(db)
})

describe('Task CRUD', () => {
  it('creates a task with all fields', () => {
    db.prepare(`
      INSERT INTO tasks (id, user_id, title, description, category_id, status, progress, due_date)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run('t1', userId, 'Build feature', 'Details here', null, 'in_progress', 25, '2025-12-01')

    const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get('t1') as Record<string, unknown>
    expect(task.title).toBe('Build feature')
    expect(task.description).toBe('Details here')
    expect(task.progress).toBe(25)
    expect(task.due_date).toBe('2025-12-01')
  })

  it('updates task fields selectively (mirrors PATCH)', () => {
    seedTask(db, userId, { id: 't1', title: 'Original', progress: 0 })

    // Simulate PATCH with only progress + status
    const updates = ['progress = ?', 'status = ?', "updated_at = datetime('now')"]
    db.prepare(`UPDATE tasks SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`)
      .run(75, 'in_progress', 't1', userId)

    const task = db.prepare('SELECT title, progress, status FROM tasks WHERE id = ?').get('t1') as {
      title: string; progress: number; status: string
    }
    expect(task.title).toBe('Original') // unchanged
    expect(task.progress).toBe(75)
    expect(task.status).toBe('in_progress')
  })

  it('marks a task as completed', () => {
    seedTask(db, userId, { id: 't1' })

    db.prepare("UPDATE tasks SET status = 'completed', progress = 100 WHERE id = ?").run('t1')

    const task = db.prepare('SELECT status, progress FROM tasks WHERE id = ?').get('t1') as {
      status: string; progress: number
    }
    expect(task.status).toBe('completed')
    expect(task.progress).toBe(100)
  })

  it('deletes a task', () => {
    seedTask(db, userId, { id: 't1' })

    const result = db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?').run('t1', userId)
    expect(result.changes).toBe(1)

    const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get('t1')
    expect(task).toBeUndefined()
  })

  it('delete returns 0 changes for wrong user', () => {
    seedTask(db, userId, { id: 't1' })

    const result = db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?').run('t1', 'wrong-user')
    expect(result.changes).toBe(0)
  })
})

describe('Task listing with filters (mirrors GET /api/tasks)', () => {
  beforeEach(() => {
    const catId = seedCategory(db, userId, { id: 'c1', name: 'Work' })
    seedTask(db, userId, { id: 't1', title: 'Fix login bug', status: 'in_progress', progress: 0, category_id: catId })
    seedTask(db, userId, { id: 't2', title: 'Add dashboard', status: 'in_progress', progress: 50 })
    seedTask(db, userId, { id: 't3', title: 'Deploy app', status: 'completed', progress: 100 })
  })

  it('lists all user tasks', () => {
    const tasks = db.prepare('SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC').all(userId)
    expect(tasks).toHaveLength(3)
  })

  it('filters by status', () => {
    const tasks = db.prepare('SELECT * FROM tasks WHERE user_id = ? AND status = ?').all(userId, 'completed')
    expect(tasks).toHaveLength(1)
  })

  it('filters by search (title LIKE)', () => {
    const tasks = db.prepare('SELECT * FROM tasks WHERE user_id = ? AND title LIKE ?').all(userId, '%bug%')
    expect(tasks).toHaveLength(1)
  })

  it('filters by category', () => {
    const tasks = db.prepare('SELECT * FROM tasks WHERE user_id = ? AND category_id = ?').all(userId, 'c1')
    expect(tasks).toHaveLength(1)
  })

  it('paginates results', () => {
    const page1 = db.prepare('SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?')
      .all(userId, 2, 0)
    const page2 = db.prepare('SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?')
      .all(userId, 2, 2)

    expect(page1).toHaveLength(2)
    expect(page2).toHaveLength(1)
  })

  it('does not return tasks from other users', () => {
    const otherUser = seedUser(db, { id: 'u2', username: 'other', email: 'other@t.com' })
    seedTask(db, otherUser, { id: 't-other', title: 'Other task' })

    const tasks = db.prepare('SELECT * FROM tasks WHERE user_id = ?').all(userId)
    expect(tasks).toHaveLength(3)
    expect(tasks.every((t: unknown) => (t as Record<string, unknown>).user_id === userId)).toBe(true)
  })
})

describe('Task with tags', () => {
  it('adds tags to a task', () => {
    seedTask(db, userId, { id: 't1' })
    db.prepare("INSERT INTO tags (id, user_id, name, color) VALUES ('tag1', ?, 'urgent', '#ef4444')").run(userId)
    db.prepare("INSERT INTO tags (id, user_id, name, color) VALUES ('tag2', ?, 'frontend', '#3b82f6')").run(userId)

    const insert = db.prepare('INSERT INTO task_tags (id, task_id, tag_id) VALUES (?, ?, ?)')
    insert.run('tt1', 't1', 'tag1')
    insert.run('tt2', 't1', 'tag2')

    const tags = db.prepare('SELECT tg.name FROM task_tags tt JOIN tags tg ON tt.tag_id = tg.id WHERE tt.task_id = ?').all('t1') as { name: string }[]
    expect(tags.map(t => t.name)).toEqual(['urgent', 'frontend'])
  })

  it('replaces tags (mirrors PATCH tag update)', () => {
    seedTask(db, userId, { id: 't1' })
    db.prepare("INSERT INTO tags (id, user_id, name, color) VALUES ('tag-old', ?, 'old-tag', '#64748b')").run(userId)
    db.prepare("INSERT INTO tags (id, user_id, name, color) VALUES ('tag-new', ?, 'new-tag', '#22c55e')").run(userId)
    db.prepare("INSERT INTO task_tags (id, task_id, tag_id) VALUES ('tt1', 't1', 'tag-old')").run()

    // Delete + re-insert (what the API does)
    db.prepare('DELETE FROM task_tags WHERE task_id = ?').run('t1')
    db.prepare("INSERT INTO task_tags (id, task_id, tag_id) VALUES ('tt2', 't1', 'tag-new')").run()

    const tags = db.prepare('SELECT tg.name FROM task_tags tt JOIN tags tg ON tt.tag_id = tg.id WHERE tt.task_id = ?').all('t1') as { name: string }[]
    expect(tags).toHaveLength(1)
    expect(tags[0].name).toBe('new-tag')
  })

  it('filters tasks by tag', () => {
    seedTask(db, userId, { id: 't1', title: 'Tagged' })
    seedTask(db, userId, { id: 't2', title: 'Not tagged' })
    db.prepare("INSERT INTO tags (id, user_id, name, color) VALUES ('tag-urg', ?, 'urgent', '#ef4444')").run(userId)
    db.prepare("INSERT INTO task_tags (id, task_id, tag_id) VALUES ('tt1', 't1', 'tag-urg')").run()

    const tasks = db.prepare(
      "SELECT * FROM tasks WHERE user_id = ? AND id IN (SELECT tt.task_id FROM task_tags tt JOIN tags tg ON tt.tag_id = tg.id WHERE tg.name = ?)"
    ).all(userId, 'urgent')
    expect(tasks).toHaveLength(1)
  })
})

describe('Task with category join (mirrors enriched GET)', () => {
  it('returns category name and color with task', () => {
    const catId = seedCategory(db, userId, { id: 'c1', name: 'Design', color: '#a855f7' })
    seedTask(db, userId, { id: 't1', category_id: catId })

    const task = db.prepare(`
      SELECT t.*, c.name as category_name, c.color as category_color
      FROM tasks t
      LEFT JOIN categories c ON t.category_id = c.id
      WHERE t.id = ?
    `).get('t1') as { category_name: string; category_color: string }

    expect(task.category_name).toBe('Design')
    expect(task.category_color).toBe('#a855f7')
  })

  it('returns null category for uncategorized task', () => {
    seedTask(db, userId, { id: 't1' })

    const task = db.prepare(`
      SELECT t.*, c.name as category_name, c.color as category_color
      FROM tasks t
      LEFT JOIN categories c ON t.category_id = c.id
      WHERE t.id = ?
    `).get('t1') as { category_name: string | null; category_color: string | null }

    expect(task.category_name).toBeNull()
    expect(task.category_color).toBeNull()
  })
})

describe('Task date update (mirrors PATCH /api/tasks/:id)', () => {
  it('saves start_date and due_date when updating a task created without dates', () => {
    // Step 1: Create task without dates (user creates task without setting dates)
    seedTask(db, userId, { id: 't1', title: 'May task', start_date: null, due_date: null })

    // Verify no dates
    const before = db.prepare('SELECT start_date, due_date FROM tasks WHERE id = ?').get('t1') as {
      start_date: string | null; due_date: string | null
    }
    expect(before.start_date).toBeNull()
    expect(before.due_date).toBeNull()

    // Step 2: Simulate PATCH with dates (exactly what the API handler does)
    const body = {
      title: 'May task',
      description: '',
      category_id: null,
      tags: [],
      start_date: '2026-05-15',
      due_date: '2026-05-20',
      progress: 0,
    }

    const allowedFields: Record<string, string> = {
      title: 'title',
      description: 'description',
      category_id: 'category_id',
      status: 'status',
      status_id: 'status_id',
      progress: 'progress',
      start_date: 'start_date',
      due_date: 'due_date',
    }

    const nullableFields = new Set(['category_id', 'status_id', 'start_date', 'due_date'])
    const updates: string[] = []
    const values: (string | number | null)[] = []

    for (const [key, col] of Object.entries(allowedFields)) {
      if (key in body) {
        updates.push(`${col} = ?`)
        const val = (body as Record<string, unknown>)[key] as string | number | null
        values.push(nullableFields.has(key) && val === '' ? null : val)
      }
    }

    updates.push("updated_at = datetime('now')")
    values.push('t1', userId)
    db.prepare(`UPDATE tasks SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`).run(...values)

    // Step 3: Verify dates are saved
    const after = db.prepare('SELECT start_date, due_date FROM tasks WHERE id = ?').get('t1') as {
      start_date: string | null; due_date: string | null
    }
    expect(after.start_date).toBe('2026-05-15')
    expect(after.due_date).toBe('2026-05-20')
  })

  it('clears dates when sending null', () => {
    seedTask(db, userId, { id: 't1', start_date: '2026-05-15', due_date: '2026-05-20' })

    // Simulate PATCH with null dates (user clears dates)
    const body = { start_date: null, due_date: null }

    const updates: string[] = []
    const values: (string | number | null)[] = []
    for (const [key, val] of Object.entries(body)) {
      updates.push(`${key} = ?`)
      values.push(val === '' ? null : val)
    }
    updates.push("updated_at = datetime('now')")
    values.push('t1', userId)
    db.prepare(`UPDATE tasks SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`).run(...values)

    const after = db.prepare('SELECT start_date, due_date FROM tasks WHERE id = ?').get('t1') as {
      start_date: string | null; due_date: string | null
    }
    expect(after.start_date).toBeNull()
    expect(after.due_date).toBeNull()
  })

  it('dates appear in SELECT t.* after update', () => {
    seedTask(db, userId, { id: 't1', start_date: null, due_date: null })

    db.prepare("UPDATE tasks SET start_date = ?, due_date = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?")
      .run('2026-05-15', '2026-05-20', 't1', userId)

    // Simulate the exact query the task list API uses
    const task = db.prepare(`
      SELECT t.*, c.name as category_name, c.color as category_color
      FROM tasks t
      LEFT JOIN categories c ON t.category_id = c.id
      WHERE t.id = ? AND t.user_id = ?
    `).get('t1', userId) as Record<string, unknown>

    expect(task.start_date).toBe('2026-05-15')
    expect(task.due_date).toBe('2026-05-20')
  })
})

describe('Kanban column mapping logic', () => {
  /**
   * The board page derives columns from status + progress:
   * - To Do:       status='in_progress', progress=0
   * - In Progress: status='in_progress', progress>0
   * - Done:        status='completed'
   */

  beforeEach(() => {
    seedTask(db, userId, { id: 'todo1', status: 'in_progress', progress: 0 })
    seedTask(db, userId, { id: 'todo2', status: 'in_progress', progress: 0 })
    seedTask(db, userId, { id: 'wip1', status: 'in_progress', progress: 30 })
    seedTask(db, userId, { id: 'wip2', status: 'in_progress', progress: 80 })
    seedTask(db, userId, { id: 'done1', status: 'completed', progress: 100 })
  })

  it('To Do: in_progress with progress=0', () => {
    const todos = db.prepare(
      "SELECT * FROM tasks WHERE user_id = ? AND status = 'in_progress' AND progress = 0"
    ).all(userId)
    expect(todos).toHaveLength(2)
  })

  it('In Progress: in_progress with progress>0', () => {
    const wip = db.prepare(
      "SELECT * FROM tasks WHERE user_id = ? AND status = 'in_progress' AND progress > 0"
    ).all(userId)
    expect(wip).toHaveLength(2)
  })

  it('Done: completed status', () => {
    const done = db.prepare(
      "SELECT * FROM tasks WHERE user_id = ? AND status = 'completed'"
    ).all(userId)
    expect(done).toHaveLength(1)
  })

  it('moving to In Progress sets progress=50', () => {
    db.prepare("UPDATE tasks SET progress = 50 WHERE id = ?").run('todo1')
    const task = db.prepare('SELECT progress, status FROM tasks WHERE id = ?').get('todo1') as {
      progress: number; status: string
    }
    expect(task.progress).toBe(50)
    expect(task.status).toBe('in_progress')
  })

  it('moving to Done sets status=completed, progress=100', () => {
    db.prepare("UPDATE tasks SET status = 'completed', progress = 100 WHERE id = ?").run('wip1')
    const task = db.prepare('SELECT progress, status FROM tasks WHERE id = ?').get('wip1') as {
      progress: number; status: string
    }
    expect(task.status).toBe('completed')
    expect(task.progress).toBe(100)
  })

  it('moving back to To Do sets status=in_progress, progress=0', () => {
    db.prepare("UPDATE tasks SET status = 'in_progress', progress = 0 WHERE id = ?").run('done1')
    const task = db.prepare('SELECT progress, status FROM tasks WHERE id = ?').get('done1') as {
      progress: number; status: string
    }
    expect(task.status).toBe('in_progress')
    expect(task.progress).toBe(0)
  })
})
