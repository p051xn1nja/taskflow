import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'

export async function GET() {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const userId = session!.user.id
  const openTaskClause = "(status_id IN (SELECT id FROM statuses WHERE user_id = ? AND is_completed = 0) OR (status_id IS NULL AND status != 'completed'))"

  const overdue = db.prepare(
    `SELECT id, title, due_date
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND date(due_date) < date('now', 'localtime')
     ORDER BY due_date ASC
     LIMIT 5`
  ).all(userId, userId)

  const dueToday = db.prepare(
    `SELECT id, title, due_date
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND date(due_date) = date('now', 'localtime')
     ORDER BY due_date ASC
     LIMIT 5`
  ).all(userId, userId)

  const upcoming = db.prepare(
    `SELECT id, title, due_date
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND date(due_date) > date('now', 'localtime')
       AND date(due_date) <= date('now', 'localtime', '+7 day')
     ORDER BY due_date ASC
     LIMIT 5`
  ).all(userId, userId)

  return NextResponse.json({
    counts: {
      overdue: overdue.length,
      due_today: dueToday.length,
      next_7_days: upcoming.length,
    },
    overdue,
    due_today: dueToday,
    upcoming,
  })
}
