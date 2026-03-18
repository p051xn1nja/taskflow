import { NextResponse } from 'next/server'
import { getDb, ensureDefaultStatuses } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import type { Task } from '@/types'

export async function GET(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const url = new URL(req.url)
  const search = url.searchParams.get('search') || ''
  const categoryId = url.searchParams.get('category_id') || ''
  const status = url.searchParams.get('status') || ''
  const statusId = url.searchParams.get('status_id') || ''
  const tag = url.searchParams.get('tag') || ''
  const dateFrom = url.searchParams.get('date_from') || ''
  const dateTo = url.searchParams.get('date_to') || ''
  const page = Math.max(1, parseInt(url.searchParams.get('page') || '1'))
  const perPage = Math.min(200, Math.max(1, parseInt(url.searchParams.get('per_page') || '50')))

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

  const countRow = db.prepare(`SELECT COUNT(*) as total FROM tasks t ${where}`).get(...params) as { total: number }
  const total = countRow.total
  const totalPages = Math.ceil(total / perPage)
  const offset = (page - 1) * perPage

  const tasks = db.prepare(`
    SELECT t.*, c.name as category_name, c.color as category_color,
      s.name as status_name, s.color as status_color, s.is_completed as status_is_completed, s.is_default as status_is_default, s.position as status_position
    FROM tasks t
    LEFT JOIN categories c ON t.category_id = c.id
    LEFT JOIN statuses s ON t.status_id = s.id
    ${where}
    ORDER BY t.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, perPage, offset) as (Task & {
    category_name: string | null; category_color: string | null
    status_name: string | null; status_color: string | null; status_is_completed: number | null; status_is_default: number | null; status_position: number | null
  })[]

  const getTagsStmt = db.prepare(`
    SELECT tg.id, tg.name, tg.color
    FROM task_tags tt
    JOIN tags tg ON tt.tag_id = tg.id
    WHERE tt.task_id = ?
  `)
  const getAttachmentsStmt = db.prepare('SELECT * FROM attachments WHERE task_id = ?')

  const enrichedTasks = tasks.map(task => ({
    ...task,
    tags: getTagsStmt.all(task.id) as { id: string; name: string; color: string }[],
    attachments: getAttachmentsStmt.all(task.id),
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

  const body = await req.json()
  const { title, description, category_id, tags, due_date, status_id } = body

  if (!title || title.trim().length === 0) {
    return NextResponse.json({ error: 'Title is required' }, { status: 400 })
  }

  if (title.length > 120) {
    return NextResponse.json({ error: 'Title too long' }, { status: 400 })
  }

  const db = getDb()
  const id = generateId()
  const userId = session!.user.id

  ensureDefaultStatuses(db, userId)

  // Resolve status_id: use provided or default
  let resolvedStatusId = status_id
  if (!resolvedStatusId) {
    const defaultStatus = db.prepare(
      'SELECT id FROM statuses WHERE user_id = ? AND is_default = 1'
    ).get(userId) as { id: string } | undefined
    resolvedStatusId = defaultStatus?.id || null
  }

  db.prepare(`
    INSERT INTO tasks (id, user_id, title, description, category_id, due_date, status_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, userId, title.trim(), (description || '').trim(), category_id || null, due_date || null, resolvedStatusId)

  // Insert tags
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

  return NextResponse.json({ id }, { status: 201 })
}
