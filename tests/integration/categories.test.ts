import { describe, it, expect, beforeEach } from 'vitest'
import type Database from 'better-sqlite3'
import { createTestDb, seedUser, seedCategory, seedTask } from '../helpers/test-db'

let db: Database.Database
let userId: string

beforeEach(() => {
  db = createTestDb()
  userId = seedUser(db)
})

describe('Category CRUD', () => {
  it('creates a category', () => {
    db.prepare('INSERT INTO categories (id, user_id, name, color) VALUES (?, ?, ?, ?)')
      .run('c1', userId, 'Work', '#3b82f6')

    const cat = db.prepare('SELECT * FROM categories WHERE id = ?').get('c1') as Record<string, unknown>
    expect(cat.name).toBe('Work')
    expect(cat.color).toBe('#3b82f6')
    expect(cat.user_id).toBe(userId)
  })

  it('updates category name and color', () => {
    seedCategory(db, userId, { id: 'c1', name: 'Old', color: '#000' })

    db.prepare('UPDATE categories SET name = ?, color = ? WHERE id = ? AND user_id = ?')
      .run('New', '#fff', 'c1', userId)

    const cat = db.prepare('SELECT name, color FROM categories WHERE id = ?').get('c1') as {
      name: string; color: string
    }
    expect(cat.name).toBe('New')
    expect(cat.color).toBe('#fff')
  })

  it('deletes a category', () => {
    seedCategory(db, userId, { id: 'c1' })

    const result = db.prepare('DELETE FROM categories WHERE id = ? AND user_id = ?').run('c1', userId)
    expect(result.changes).toBe(1)
  })

  it('delete ignores wrong user', () => {
    seedCategory(db, userId, { id: 'c1' })

    const result = db.prepare('DELETE FROM categories WHERE id = ? AND user_id = ?').run('c1', 'wrong')
    expect(result.changes).toBe(0)
  })
})

describe('Category listing with task count (mirrors GET /api/categories)', () => {
  it('returns categories with task_count', () => {
    seedCategory(db, userId, { id: 'c1', name: 'Work' })
    seedCategory(db, userId, { id: 'c2', name: 'Personal' })
    seedTask(db, userId, { id: 't1', category_id: 'c1' })
    seedTask(db, userId, { id: 't2', category_id: 'c1' })
    seedTask(db, userId, { id: 't3', category_id: 'c2' })

    const categories = db.prepare(`
      SELECT c.*, COUNT(t.id) as task_count
      FROM categories c
      LEFT JOIN tasks t ON c.id = t.category_id
      WHERE c.user_id = ?
      GROUP BY c.id
      ORDER BY c.name ASC
    `).all(userId) as { name: string; task_count: number }[]

    expect(categories).toHaveLength(2)
    expect(categories[0].name).toBe('Personal')
    expect(categories[0].task_count).toBe(1)
    expect(categories[1].name).toBe('Work')
    expect(categories[1].task_count).toBe(2)
  })

  it('returns 0 task_count for empty category', () => {
    seedCategory(db, userId, { id: 'c1', name: 'Empty' })

    const categories = db.prepare(`
      SELECT c.*, COUNT(t.id) as task_count
      FROM categories c
      LEFT JOIN tasks t ON c.id = t.category_id
      WHERE c.user_id = ?
      GROUP BY c.id
    `).all(userId) as { task_count: number }[]

    expect(categories[0].task_count).toBe(0)
  })

  it('does not list categories from other users', () => {
    const otherUser = seedUser(db, { id: 'u2', username: 'other', email: 'o@t.com' })
    seedCategory(db, userId, { id: 'c1', name: 'Mine' })
    seedCategory(db, otherUser, { id: 'c2', name: 'Theirs' })

    const cats = db.prepare('SELECT * FROM categories WHERE user_id = ?').all(userId)
    expect(cats).toHaveLength(1)
  })
})
