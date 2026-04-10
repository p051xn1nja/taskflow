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
  const now = new Date()
  const today = [
    now.getFullYear().toString().padStart(4, '0'),
    (now.getMonth() + 1).toString().padStart(2, '0'),
    now.getDate().toString().padStart(2, '0'),
  ].join('-')
  const next7 = new Date(now)
  next7.setDate(next7.getDate() + 7)
  const next7Date = [
    next7.getFullYear().toString().padStart(4, '0'),
    (next7.getMonth() + 1).toString().padStart(2, '0'),
    next7.getDate().toString().padStart(2, '0'),
  ].join('-')
  const openTaskClause = "(status_id IN (SELECT id FROM statuses WHERE user_id = ? AND is_completed = 0) OR (status_id IS NULL AND status != 'completed'))"

  const overdueCountRow = db.prepare(
    `SELECT COUNT(*) as total
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND due_date < ?`
  ).get(userId, userId, today) as { total: number }

  const dueTodayCountRow = db.prepare(
    `SELECT COUNT(*) as total
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND due_date = ?`
  ).get(userId, userId, today) as { total: number }

  const upcomingCountRow = db.prepare(
    `SELECT COUNT(*) as total
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND due_date > ?
       AND due_date <= ?`
  ).get(userId, userId, today, next7Date) as { total: number }

  const overdue = includeItems ? db.prepare(
    `SELECT id, title, due_date
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND due_date < ?
     ORDER BY due_date ASC
     LIMIT ?`
  ).all(userId, userId, today, limit) : []

  const dueToday = includeItems ? db.prepare(
    `SELECT id, title, due_date
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND due_date = ?
     ORDER BY due_date ASC
     LIMIT ?`
  ).all(userId, userId, today, limit) : []

  const upcoming = includeItems ? db.prepare(
    `SELECT id, title, due_date
     FROM tasks
     WHERE user_id = ?
       AND ${openTaskClause}
       AND due_date IS NOT NULL
       AND due_date > ?
       AND due_date <= ?
     ORDER BY due_date ASC
     LIMIT ?`
  ).all(userId, userId, today, next7Date, limit) : []

  let notificationDispatched = false
  let notificationReason: 'not_requested' | 'dispatched' | 'no_webhook_configured' | 'no_pending_reminders' | 'webhook_failed' = 'not_requested'
  const hasAnyReminders = overdueCountRow.total > 0 || dueTodayCountRow.total > 0 || upcomingCountRow.total > 0
  if (shouldNotify) {
    if (!hasAnyReminders) {
      notificationReason = 'no_pending_reminders'
    } else if (!process.env.REMINDER_WEBHOOK_URL) {
      notificationReason = 'no_webhook_configured'
    } else {
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
        notificationReason = res.ok ? 'dispatched' : 'webhook_failed'
      } catch {
        notificationDispatched = false
        notificationReason = 'webhook_failed'
      }
    }
  }

  return NextResponse.json({
    meta: {
      limit_applied: limit,
      generated_at: new Date().toISOString(),
      notification_attempted: shouldNotify,
      notification_dispatched: notificationDispatched,
      notification_available: Boolean(process.env.REMINDER_WEBHOOK_URL),
      notification_reason: notificationReason,
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
