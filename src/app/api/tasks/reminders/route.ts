import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'

export async function GET() {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const userId = session!.user.id
  const today = new Date().toISOString().slice(0, 10)

  const overdue = db.prepare(
    "SELECT id, title, due_date FROM tasks WHERE user_id = ? AND status != 'completed' AND due_date IS NOT NULL AND date(due_date) < date(?) ORDER BY due_date ASC LIMIT 5"
  ).all(userId, today)

  const dueToday = db.prepare(
    "SELECT id, title, due_date FROM tasks WHERE user_id = ? AND status != 'completed' AND due_date IS NOT NULL AND date(due_date) = date(?) ORDER BY due_date ASC LIMIT 5"
  ).all(userId, today)

  const upcoming = db.prepare(
    "SELECT id, title, due_date FROM tasks WHERE user_id = ? AND status != 'completed' AND due_date IS NOT NULL AND date(due_date) > date(?) AND date(due_date) <= date(?, '+7 day') ORDER BY due_date ASC LIMIT 5"
  ).all(userId, today, today)

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
