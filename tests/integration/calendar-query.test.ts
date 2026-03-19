import { describe, it, expect, beforeEach } from 'vitest'
import Database from 'better-sqlite3'
import { createTestDb, seedUser, seedTask, seedStatuses } from '../helpers/test-db'

/**
 * Tests for the calendar API query logic.
 * Replicates the exact SQL from /api/calendar/route.ts to verify
 * tasks are correctly returned for given date ranges.
 */

function queryCalendarTasks(
  db: Database.Database,
  userId: string,
  dateFrom: string,
  dateTo: string
) {
  const taskWhere = `WHERE t.user_id = ? AND (
    (t.start_date IS NOT NULL AND t.due_date IS NOT NULL AND date(t.start_date) <= ? AND date(t.due_date) >= ?) OR
    (t.start_date IS NULL AND t.due_date IS NOT NULL AND date(t.due_date) >= ? AND date(t.due_date) <= ?) OR
    (t.start_date IS NOT NULL AND t.due_date IS NULL AND date(t.start_date) >= ? AND date(t.start_date) <= ?) OR
    (t.start_date IS NULL AND t.due_date IS NULL AND date(t.created_at) >= ? AND date(t.created_at) <= ?)
  )`
  const taskParams = [userId, dateTo, dateFrom, dateFrom, dateTo, dateFrom, dateTo, dateFrom, dateTo]

  return db.prepare(`
    SELECT t.id, t.title, t.start_date, t.due_date, t.created_at
    FROM tasks t
    ${taskWhere}
    ORDER BY COALESCE(t.start_date, t.due_date, t.created_at)
  `).all(...taskParams) as { id: string; title: string; start_date: string | null; due_date: string | null; created_at: string }[]
}

describe('Calendar query - May tasks', () => {
  let db: Database.Database
  let userId: string

  // May 2026 month view range: grid starts Monday April 27, ends Sunday May 31
  const MAY_FROM = '2026-04-27'
  const MAY_TO = '2026-05-31'

  beforeEach(() => {
    db = createTestDb()
    userId = seedUser(db)
    seedStatuses(db, userId)
  })

  it('finds task with only due_date in May', () => {
    seedTask(db, userId, { id: 't1', title: 'May Due Task', due_date: '2026-05-15' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(1)
    expect(results[0].title).toBe('May Due Task')
  })

  it('finds task with only start_date in May', () => {
    seedTask(db, userId, { id: 't2', title: 'May Start Task', start_date: '2026-05-10' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(1)
    expect(results[0].title).toBe('May Start Task')
  })

  it('finds task with both start_date and due_date in May', () => {
    seedTask(db, userId, { id: 't3', title: 'May Range', start_date: '2026-05-01', due_date: '2026-05-15' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(1)
    expect(results[0].title).toBe('May Range')
  })

  it('finds range task that starts in April and ends in May', () => {
    seedTask(db, userId, { id: 't4', title: 'Apr-May Span', start_date: '2026-04-20', due_date: '2026-05-10' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(1)
    expect(results[0].title).toBe('Apr-May Span')
  })

  it('finds range task that starts in May and ends in June', () => {
    seedTask(db, userId, { id: 't5', title: 'May-Jun Span', start_date: '2026-05-25', due_date: '2026-06-10' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(1)
    expect(results[0].title).toBe('May-Jun Span')
  })

  it('finds task with due_date on first day of May range (Apr 27)', () => {
    seedTask(db, userId, { id: 't6', title: 'Grid Start Task', due_date: '2026-04-27' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(1)
  })

  it('finds task with due_date on last day of May range (May 31)', () => {
    seedTask(db, userId, { id: 't7', title: 'Grid End Task', due_date: '2026-05-31' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(1)
  })

  it('excludes task with due_date before range', () => {
    seedTask(db, userId, { id: 't8', title: 'Before Range', due_date: '2026-04-26' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(0)
  })

  it('excludes task with due_date after range', () => {
    seedTask(db, userId, { id: 't9', title: 'After Range', due_date: '2026-06-01' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(0)
  })

  it('finds task with no dates when created_at is in May range', () => {
    // Manually insert with explicit created_at in May
    db.prepare(`
      INSERT INTO tasks (id, user_id, title, description, status, progress, created_at, updated_at)
      VALUES (?, ?, ?, '', 'in_progress', 0, '2026-05-10 12:00:00', '2026-05-10 12:00:00')
    `).run('t10', userId, 'Created In May')
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(1)
    expect(results[0].title).toBe('Created In May')
  })

  it('excludes task with no dates when created_at is NOT in May range', () => {
    db.prepare(`
      INSERT INTO tasks (id, user_id, title, description, status, progress, created_at, updated_at)
      VALUES (?, ?, ?, '', 'in_progress', 0, '2026-03-15 12:00:00', '2026-03-15 12:00:00')
    `).run('t11', userId, 'Created In March')
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(0)
  })

  it('finds multiple May tasks simultaneously', () => {
    seedTask(db, userId, { id: 'a', title: 'A', due_date: '2026-05-01' })
    seedTask(db, userId, { id: 'b', title: 'B', start_date: '2026-05-15' })
    seedTask(db, userId, { id: 'c', title: 'C', start_date: '2026-05-01', due_date: '2026-05-31' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(3)
  })

  it('excludes tasks from other users', () => {
    const otherUser = seedUser(db, { id: 'other', username: 'other', email: 'other@test.com' })
    seedTask(db, otherUser, { id: 'other-t', title: 'Other Task', due_date: '2026-05-15' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(0)
  })

  // Test with year view range (full year)
  it('finds May task in year view', () => {
    seedTask(db, userId, { id: 't-yr', title: 'May Year Task', due_date: '2026-05-15' })
    const results = queryCalendarTasks(db, userId, '2026-01-01', '2026-12-31')
    expect(results).toHaveLength(1)
    expect(results[0].title).toBe('May Year Task')
  })

  // Edge case: task with start_date only on May 1
  it('finds task with start_date on May 1', () => {
    seedTask(db, userId, { id: 't-may1', title: 'May 1st Start', start_date: '2026-05-01' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(1)
  })

  // Edge case: range task that fully encloses the view range
  it('finds range task that spans entire view and beyond', () => {
    seedTask(db, userId, { id: 't-big', title: 'Huge Range', start_date: '2026-01-01', due_date: '2026-12-31' })
    const results = queryCalendarTasks(db, userId, MAY_FROM, MAY_TO)
    expect(results).toHaveLength(1)
    expect(results[0].title).toBe('Huge Range')
  })
})
