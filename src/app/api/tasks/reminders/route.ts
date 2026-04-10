import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { parsePositiveInt } from '@/lib/utils'

export async function GET(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const url = new URL(req.url)
  const limit = parsePositiveInt(url.searchParams.get('limit'), 5, 20)
  const includeItemsParam = url.searchParams.get('include_items')
  const includeItems = !(includeItemsParam === '0' || includeItemsParam?.toLowerCase() === 'false')
  const notifyParam = url.searchParams.get('notify')
  const shouldNotify = notifyParam === '1' || notifyParam?.toLowerCase() === 'true'
  const db = getDb()
  const userId = session!.user.id
  const openTaskClause = "(status_id IN (SELECT id FROM statuses WHERE user_id = ? AND is_completed = 0) OR (status_id IS NULL AND status != 'completed'))"

  const overdueCountRow = db.prepare(
    `SELECT COUNT(*) as total
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND date(due_date) < date('now', 'localtime')`
  ).get(userId, userId) as { total: number }

  const dueTodayCountRow = db.prepare(
    `SELECT COUNT(*) as total
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND date(due_date) = date('now', 'localtime')`
  ).get(userId, userId) as { total: number }

  const upcomingCountRow = db.prepare(
    `SELECT COUNT(*) as total
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND date(due_date) > date('now', 'localtime')
       AND date(due_date) <= date('now', 'localtime', '+7 day')`
  ).get(userId, userId) as { total: number }

  const overdue = includeItems ? db.prepare(
    `SELECT id, title, due_date
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND date(due_date) < date('now', 'localtime')
     ORDER BY due_date ASC
     LIMIT ?`
  ).all(userId, userId, limit) : []

  const dueToday = includeItems ? db.prepare(
    `SELECT id, title, due_date
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND date(due_date) = date('now', 'localtime')
     ORDER BY due_date ASC
     LIMIT ?`
  ).all(userId, userId, limit) : []

  const upcoming = includeItems ? db.prepare(
    `SELECT id, title, due_date
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND date(due_date) > date('now', 'localtime')
       AND date(due_date) <= date('now', 'localtime', '+7 day')
     ORDER BY due_date ASC
     LIMIT ?`
  ).all(userId, userId, limit) : []

  let notificationDispatched = false
  const hasAnyReminders = overdueCountRow.total > 0 || dueTodayCountRow.total > 0 || upcomingCountRow.total > 0
  if (shouldNotify && hasAnyReminders && process.env.REMINDER_WEBHOOK_URL) {
    try {
      const res = await fetch(process.env.REMINDER_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          counts: {
            overdue: overdueCountRow.total,
            due_today: dueTodayCountRow.total,
            next_7_days: upcomingCountRow.total,
          },
          generated_at: new Date().toISOString(),
        }),
      })
      notificationDispatched = res.ok
    } catch {
      notificationDispatched = false
    }
  }

  return NextResponse.json({
    meta: {
      limit_applied: limit,
      generated_at: new Date().toISOString(),
      notification_attempted: shouldNotify,
      notification_dispatched: notificationDispatched,
      notification_available: Boolean(process.env.REMINDER_WEBHOOK_URL),
    },
    counts: {
      overdue: overdueCountRow.total,
      due_today: dueTodayCountRow.total,
      next_7_days: upcomingCountRow.total,
    },
    overdue,
    due_today: dueToday,
    upcoming,
  })
}
