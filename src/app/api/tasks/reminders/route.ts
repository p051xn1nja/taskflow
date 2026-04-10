import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'

export async function GET() {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const userId = session!.user.id
  const today = new Date().toISOString().slice(0, 10)
  const tomorrowDate = new Date()
  tomorrowDate.setDate(tomorrowDate.getDate() + 1)
  const tomorrow = tomorrowDate.toISOString().slice(0, 10)

  const overdue = db.prepare(
    `SELECT id, title, due_date, progress
     FROM tasks
     WHERE user_id = ?
       AND due_date IS NOT NULL
       AND date(due_date) < date(?)
       AND progress < 100
     ORDER BY due_date ASC
     LIMIT 20`
  ).all(userId, today)

  const dueToday = db.prepare(
    `SELECT id, title, due_date, progress
     FROM tasks
     WHERE user_id = ?
       AND due_date IS NOT NULL
       AND date(due_date) = date(?)
       AND progress < 100
     ORDER BY due_date ASC
     LIMIT 20`
  ).all(userId, today)

  const dueTomorrow = db.prepare(
    `SELECT id, title, due_date, progress
     FROM tasks
     WHERE user_id = ?
       AND due_date IS NOT NULL
       AND date(due_date) = date(?)
       AND progress < 100
     ORDER BY due_date ASC
     LIMIT 20`
  ).all(userId, tomorrow)

  return NextResponse.json({
    counts: {
      overdue: overdue.length,
      due_today: dueToday.length,
      due_tomorrow: dueTomorrow.length,
    },
    overdue,
    due_today: dueToday,
    due_tomorrow: dueTomorrow,
  })
}
