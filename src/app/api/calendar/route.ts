import { NextResponse } from 'next/server'
import { getDb, ensureDefaultStatuses } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'

export async function GET(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const url = new URL(req.url)
  const dateFrom = url.searchParams.get('date_from') || ''
  const dateTo = url.searchParams.get('date_to') || ''
  const categoryId = url.searchParams.get('category_id') || ''
  const statusId = url.searchParams.get('status_id') || ''
  const tag = url.searchParams.get('tag') || ''
  const types = url.searchParams.get('types') || 'all' // 'all', 'tasks', 'notes'

  if (!dateFrom || !dateTo) {
    return NextResponse.json({ error: 'date_from and date_to required' }, { status: 400 })
  }

  const db = getDb()
  const userId = session!.user.id

  ensureDefaultStatuses(db, userId)

  const items: { date: string; type: 'task' | 'note'; id: string; title: string; color: string; status_name?: string; status_color?: string; is_completed?: boolean; progress?: number; category_name?: string; category_color?: string; start_date?: string; end_date?: string }[] = []

  // Fetch tasks that overlap the date range (have start_date or due_date)
  if (types === 'all' || types === 'tasks') {
    // A task is visible if its date range overlaps the query range
    // Tasks with only due_date: shown on due_date (legacy)
    // Tasks with start_date and due_date: shown as a range
    // Tasks with only start_date: shown on start_date
    let taskWhere = `WHERE t.user_id = ? AND (
      (t.start_date IS NOT NULL AND t.due_date IS NOT NULL AND date(t.start_date) <= ? AND date(t.due_date) >= ?) OR
      (t.start_date IS NULL AND t.due_date IS NOT NULL AND date(t.due_date) >= ? AND date(t.due_date) <= ?) OR
      (t.start_date IS NOT NULL AND t.due_date IS NULL AND date(t.start_date) >= ? AND date(t.start_date) <= ?) OR
      (t.start_date IS NULL AND t.due_date IS NULL AND date(t.created_at) >= ? AND date(t.created_at) <= ?)
    )`
    const taskParams: (string | number)[] = [userId, dateTo, dateFrom, dateFrom, dateTo, dateFrom, dateTo, dateFrom, dateTo]

    if (categoryId) {
      taskWhere += ' AND t.category_id = ?'
      taskParams.push(categoryId)
    }
    if (statusId) {
      taskWhere += ' AND t.status_id = ?'
      taskParams.push(statusId)
    }
    if (tag) {
      taskWhere += ' AND t.id IN (SELECT tt.task_id FROM task_tags tt JOIN tags tg ON tt.tag_id = tg.id WHERE tg.name = ?)'
      taskParams.push(tag)
    }

    const tasks = db.prepare(`
      SELECT t.id, t.title, t.start_date, t.due_date, t.progress, t.created_at,
        s.name as status_name, s.color as status_color, s.is_completed,
        c.name as category_name, c.color as category_color
      FROM tasks t
      LEFT JOIN statuses s ON t.status_id = s.id
      LEFT JOIN categories c ON t.category_id = c.id
      ${taskWhere}
      ORDER BY COALESCE(t.start_date, t.due_date, t.created_at)
    `).all(...taskParams) as {
      id: string; title: string; start_date: string | null; due_date: string | null; progress: number; created_at: string
      status_name: string | null; status_color: string | null; is_completed: number | null
      category_name: string | null; category_color: string | null
    }[]

    for (const t of tasks) {
      items.push({
        date: t.start_date || t.due_date || t.created_at.split(/[T ]/)[0],
        type: 'task',
        id: t.id,
        title: t.title,
        color: t.category_color || t.status_color || '#3b82f6',
        status_name: t.status_name || undefined,
        status_color: t.status_color || undefined,
        is_completed: t.is_completed === 1,
        progress: t.progress,
        category_name: t.category_name || undefined,
        category_color: t.category_color || undefined,
        start_date: t.start_date || undefined,
        end_date: t.due_date || undefined,
      })
    }
  }

  // Fetch notes by created_at
  if (types === 'all' || types === 'notes') {
    let noteWhere = 'WHERE n.user_id = ? AND date(n.created_at) >= ? AND date(n.created_at) <= ?'
    const noteParams: (string | number)[] = [userId, dateFrom, dateTo]

    if (tag) {
      noteWhere += ' AND n.id IN (SELECT nt.note_id FROM note_tags nt JOIN tags tg ON nt.tag_id = tg.id WHERE tg.name = ?)'
      noteParams.push(tag)
    }

    const notes = db.prepare(`
      SELECT n.id, n.title, n.created_at
      FROM notes n
      ${noteWhere}
      ORDER BY n.created_at
    `).all(...noteParams) as { id: string; title: string; created_at: string }[]

    for (const n of notes) {
      items.push({
        date: n.created_at.split(/[T ]/)[0],
        type: 'note',
        id: n.id,
        title: n.title,
        color: '#a855f7',
      })
    }
  }

  return NextResponse.json({ items })
}
