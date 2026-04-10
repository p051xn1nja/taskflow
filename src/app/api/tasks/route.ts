import { NextResponse } from 'next/server'
import { getDb, ensureDefaultStatuses } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId, parsePositiveInt } from '@/lib/utils'
import { getPlatformSettings } from '@/lib/platform-settings'
import type { Task } from '@/types'
import { z } from 'zod'

const CreateTaskSchema = z.object({
  title: z.string().trim().min(1).max(120),
  description: z.string().max(20_000).optional(),
  category_id: z.string().optional().nullable(),
  tags: z.array(z.string()).max(10).optional(),
  start_date: z.string().optional().nullable(),
  due_date: z.string().optional().nullable(),
  status_id: z.string().optional().nullable(),
  location: z.string().max(200).optional(),
  recurrence: z.enum(['none', 'daily', 'weekly', 'monthly']).optional(),
})

const TaskViewParamSchema = z.enum(['inbox', 'today', 'upcoming', 'overdue', 'no_status'])
const YmdDateParamSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/)
const SearchParamSchema = z.string().trim().max(120)
const TagParamSchema = z.string().trim().max(60)
const IdParamSchema = z.string().trim().min(1).max(48)

export async function GET(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const url = new URL(req.url)
  const rawSearch = url.searchParams.get('search')
  const search = rawSearch && SearchParamSchema.safeParse(rawSearch).success ? rawSearch.trim() : ''
  const rawCategoryId = url.searchParams.get('category_id')
  const categoryId = rawCategoryId && IdParamSchema.safeParse(rawCategoryId).success ? rawCategoryId.trim() : ''
  const status = url.searchParams.get('status') || ''
  const rawStatusId = url.searchParams.get('status_id')
  const statusId = rawStatusId && IdParamSchema.safeParse(rawStatusId).success ? rawStatusId.trim() : ''
  const rawTag = url.searchParams.get('tag')
  const tag = rawTag && TagParamSchema.safeParse(rawTag).success ? rawTag.trim() : ''
  const rawView = url.searchParams.get('view')
  const view = rawView ? (TaskViewParamSchema.safeParse(rawView).success ? rawView : '') : ''
  const rawDateFrom = url.searchParams.get('date_from')
  const rawDateTo = url.searchParams.get('date_to')
  const dateFrom = rawDateFrom && YmdDateParamSchema.safeParse(rawDateFrom).success ? rawDateFrom : ''
  const dateTo = rawDateTo && YmdDateParamSchema.safeParse(rawDateTo).success ? rawDateTo : ''
  const page = parsePositiveInt(url.searchParams.get('page'), 1)
  const perPage = parsePositiveInt(url.searchParams.get('per_page'), 50, 200)

  const db = getDb()
  const userId = session!.user.id

  ensureDefaultStatuses(db, userId)

  let where = 'WHERE t.user_id = ?'
  const params: (string | number)[] = [userId]

  if (search) {
    where += ' AND (t.title LIKE ? OR t.description LIKE ?)'
    params.push(`%${search}%`, `%${search}%`)
  }
  if (categoryId) {
    where += ' AND t.category_id = ?'
    params.push(categoryId)
  }
  if (statusId) {
    where += ' AND t.status_id = ?'
    params.push(statusId)
  } else if (status) {
    // Legacy filter: map 'in_progress' / 'completed' to status is_completed flag
    if (status === 'completed') {
      where += ' AND t.status_id IN (SELECT id FROM statuses WHERE user_id = ? AND is_completed = 1)'
      params.push(userId)
    } else {
      where += ' AND t.status_id IN (SELECT id FROM statuses WHERE user_id = ? AND is_completed = 0)'
      params.push(userId)
    }
  }
  if (dateFrom) {
    where += ' AND date(t.created_at) >= ?'
    params.push(dateFrom)
  }
  if (dateTo) {
    where += ' AND date(t.created_at) <= ?'
    params.push(dateTo)
  }
  if (tag) {
    where += ' AND t.id IN (SELECT tt.task_id FROM task_tags tt JOIN tags tg ON tt.tag_id = tg.id WHERE tg.name = ?)'
    params.push(tag)
  }
  if (view) {
    const today = new Date().toISOString().slice(0, 10)
    const notCompletedClause = "(t.status_id IN (SELECT id FROM statuses WHERE user_id = ? AND is_completed = 0) OR (t.status_id IS NULL AND t.status != 'completed'))"
    if (view === 'inbox') {
      where += ` AND t.start_date IS NULL AND t.due_date IS NULL AND ${notCompletedClause}`
      params.push(userId)
    } else if (view === 'today') {
      where += ` AND ((t.start_date IS NOT NULL AND t.due_date IS NOT NULL AND date(?) BETWEEN date(t.start_date) AND date(t.due_date)) OR (t.due_date IS NOT NULL AND date(t.due_date) = date(?)) OR (t.start_date IS NOT NULL AND t.due_date IS NULL AND date(t.start_date) = date(?))) AND ${notCompletedClause}`
      params.push(today, today, today, userId)
    } else if (view === 'upcoming') {
      where += ` AND ((t.due_date IS NOT NULL AND date(t.due_date) > date(?)) OR (t.start_date IS NOT NULL AND date(t.start_date) > date(?))) AND ${notCompletedClause}`
      params.push(today, today, userId)
    } else if (view === 'overdue') {
      where += ` AND t.due_date IS NOT NULL AND date(t.due_date) < date(?) AND ${notCompletedClause}`
      params.push(today, userId)
    } else if (view === 'no_status') {
      where += ' AND t.status_id IS NULL'
    }
  }

  const countRow = db.prepare(`SELECT COUNT(*) as total FROM tasks t ${where}`).get(...params) as { total: number }
  const total = countRow.total
  const totalPages = Math.ceil(total / perPage)
  const offset = (page - 1) * perPage

  const tasks = db.prepare(`
    SELECT t.*, c.name as category_name, c.color as category_color,
      s.name as status_name, s.color as status_color, s.is_completed as status_is_completed, s.is_default as status_is_default, s.position as status_position
    FROM tasks t
    LEFT JOIN categories c ON t.category_id = c.id
    LEFT JOIN statuses s ON t.status_id = s.id AND s.user_id = t.user_id
    ${where}
    ORDER BY t.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, perPage, offset) as (Task & {
    category_name: string | null; category_color: string | null
    status_name: string | null; status_color: string | null; status_is_completed: number | null; status_is_default: number | null; status_position: number | null
  })[]

  const taskIds = tasks.map(t => t.id)
  const tagsByTask = new Map<string, { id: string; name: string; color: string }[]>()
  const attachmentsByTask = new Map<string, Record<string, unknown>[]>()

  if (taskIds.length > 0) {
    const placeholders = taskIds.map(() => '?').join(', ')
    const tags = db.prepare(`
      SELECT tt.task_id, tg.id, tg.name, tg.color
      FROM task_tags tt
      JOIN tags tg ON tt.tag_id = tg.id
      WHERE tt.task_id IN (${placeholders})
    `).all(...taskIds) as { task_id: string; id: string; name: string; color: string }[]

    const attachments = db.prepare(`
      SELECT * FROM attachments
      WHERE task_id IN (${placeholders})
    `).all(...taskIds) as (Record<string, unknown> & { task_id: string })[]

    for (const tagRow of tags) {
      const current = tagsByTask.get(tagRow.task_id) || []
      current.push({ id: tagRow.id, name: tagRow.name, color: tagRow.color })
      tagsByTask.set(tagRow.task_id, current)
    }

    for (const attachmentRow of attachments) {
      const current = attachmentsByTask.get(attachmentRow.task_id) || []
      current.push(attachmentRow)
      attachmentsByTask.set(attachmentRow.task_id, current)
    }
  }

  const enrichedTasks = tasks.map(task => ({
    ...task,
    tags: tagsByTask.get(task.id) || [],
    attachments: attachmentsByTask.get(task.id) || [],
    category: task.category_id ? { id: task.category_id, name: task.category_name!, color: task.category_color! } : null,
    task_status: task.status_id ? {
      id: task.status_id,
      name: task.status_name!,
      color: task.status_color!,
      is_completed: task.status_is_completed === 1,
      is_default: task.status_is_default === 1,
      position: task.status_position ?? 0,
    } : null,
  }))

  return NextResponse.json({
    tasks: enrichedTasks,
    pagination: { page, per_page: perPage, total, total_pages: totalPages },
  })
}

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const parsed = CreateTaskSchema.safeParse(await req.json())
  if (!parsed.success) return NextResponse.json({ error: 'Invalid input' }, { status: 400 })
  const { title, description, category_id, tags, start_date, due_date, status_id, location, recurrence } = parsed.data

  const db = getDb()
  const id = generateId()
  const userId = session!.user.id
  const settings = getPlatformSettings(db)

  const taskCount = db.prepare('SELECT COUNT(*) as count FROM tasks WHERE user_id = ?').get(userId) as { count: number }
  if (taskCount.count >= settings.maxTasksPerUser) {
    return NextResponse.json({ error: `Task limit reached (${settings.maxTasksPerUser})` }, { status: 400 })
  }

  ensureDefaultStatuses(db, userId)

  // Resolve status_id: use provided or default
  let resolvedStatusId = status_id
  if (!resolvedStatusId) {
    const defaultStatus = db.prepare(
      'SELECT id FROM statuses WHERE user_id = ? AND is_default = 1'
    ).get(userId) as { id: string } | undefined
    resolvedStatusId = defaultStatus?.id || null
  } else {
    const statusRow = db.prepare('SELECT id FROM statuses WHERE id = ? AND user_id = ?').get(resolvedStatusId, userId)
    if (!statusRow) return NextResponse.json({ error: 'Invalid status_id' }, { status: 400 })
  }

  const createTaskTx = db.transaction(() => {
    db.prepare(`
      INSERT INTO tasks (id, user_id, title, description, category_id, start_date, due_date, status_id, location, recurrence)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, userId, title.trim(), (description || '').trim(), category_id || null, start_date || null, due_date || null, resolvedStatusId, (location || '').trim(), recurrence || 'none')

    if (tags && Array.isArray(tags)) {
      const findTag = db.prepare('SELECT id FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE')
      const insertTag = db.prepare('INSERT INTO tags (id, user_id, name, color) VALUES (?, ?, ?, ?)')
      const insertTaskTag = db.prepare('INSERT INTO task_tags (id, task_id, tag_id) VALUES (?, ?, ?)')

      for (const tagName of tags.slice(0, 10)) {
        const trimmed = typeof tagName === 'string' ? tagName.trim().slice(0, 30) : ''
        if (!trimmed) continue

        let tagRow = findTag.get(userId, trimmed) as { id: string } | undefined
        if (!tagRow) {
          const newTagId = generateId()
          insertTag.run(newTagId, userId, trimmed, '#3b82f6')
          tagRow = { id: newTagId }
        }

        insertTaskTag.run(generateId(), id, tagRow.id)
      }
    }
  })

  createTaskTx()

  return NextResponse.json({ id }, { status: 201 })
}
