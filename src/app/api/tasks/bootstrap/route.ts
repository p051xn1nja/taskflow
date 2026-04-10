import { NextResponse } from 'next/server'
import { ensureDefaultStatuses, getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'

export async function POST() {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const userId = session!.user.id

  const taskCount = db.prepare('SELECT COUNT(*) as c FROM tasks WHERE user_id = ?').get(userId) as { c: number }
  if (taskCount.c > 0) {
    return NextResponse.json({ error: 'Tasks already exist' }, { status: 400 })
  }

  ensureDefaultStatuses(db, userId)
  const defaultStatus = db.prepare('SELECT id FROM statuses WHERE user_id = ? AND is_default = 1').get(userId) as { id: string } | undefined

  const insertTask = db.prepare(`
    INSERT INTO tasks (id, user_id, title, description, status, status_id, progress, due_date)
    VALUES (?, ?, ?, ?, 'in_progress', ?, ?, ?)
  `)

  const today = new Date()
  const tomorrow = new Date(today)
  tomorrow.setDate(today.getDate() + 1)
  const in3Days = new Date(today)
  in3Days.setDate(today.getDate() + 3)
  const fmt = (d: Date) => d.toISOString().slice(0, 10)

  insertTask.run(generateId(), userId, 'Plan your week', 'Review priorities and set realistic goals for this week.', defaultStatus?.id || null, 10, fmt(tomorrow))
  insertTask.run(generateId(), userId, 'Capture ideas in Notes', 'Use notes to collect ideas and link relevant tasks.', defaultStatus?.id || null, 0, fmt(in3Days))
  insertTask.run(generateId(), userId, 'Set up a recurring review', 'Create a recurring task for your weekly review ritual.', defaultStatus?.id || null, 0, null)

  return NextResponse.json({ success: true })
}
