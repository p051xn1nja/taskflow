import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
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
  const tag = url.searchParams.get('tag') || ''
  const dateFrom = url.searchParams.get('date_from') || ''
  const dateTo = url.searchParams.get('date_to') || ''
  const page = Math.max(1, parseInt(url.searchParams.get('page') || '1'))
  const perPage = Math.min(200, Math.max(1, parseInt(url.searchParams.get('per_page') || '50')))

  const db = getDb()
  const userId = session!.user.id

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
  if (status) {
    where += ' AND t.status = ?'
    params.push(status)
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
    where += ' AND t.id IN (SELECT task_id FROM task_tags WHERE name = ?)'
    params.push(tag)
  }

  const countRow = db.prepare(`SELECT COUNT(*) as total FROM tasks t ${where}`).get(...params) as { total: number }
  const total = countRow.total
  const totalPages = Math.ceil(total / perPage)
  const offset = (page - 1) * perPage

  const tasks = db.prepare(`
    SELECT t.*, c.name as category_name, c.color as category_color
    FROM tasks t
    LEFT JOIN categories c ON t.category_id = c.id
    ${where}
    ORDER BY t.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, perPage, offset) as (Task & { category_name: string | null; category_color: string | null })[]

  // Get tags and attachments for each task
  const getTagsStmt = db.prepare('SELECT name FROM task_tags WHERE task_id = ?')
  const getAttachmentsStmt = db.prepare('SELECT * FROM attachments WHERE task_id = ?')

  const enrichedTasks = tasks.map(task => ({
    ...task,
    tags: (getTagsStmt.all(task.id) as { name: string }[]).map(t => t.name),
    attachments: getAttachmentsStmt.all(task.id),
    category: task.category_id ? { id: task.category_id, name: task.category_name!, color: task.category_color! } : null,
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
  const { title, description, category_id, tags, due_date } = body

  if (!title || title.trim().length === 0) {
    return NextResponse.json({ error: 'Title is required' }, { status: 400 })
  }

  if (title.length > 120) {
    return NextResponse.json({ error: 'Title too long' }, { status: 400 })
  }

  const db = getDb()
  const id = generateId()
  const userId = session!.user.id

  db.prepare(`
    INSERT INTO tasks (id, user_id, title, description, category_id, due_date)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, userId, title.trim(), (description || '').trim(), category_id || null, due_date || null)

  // Insert tags
  if (tags && Array.isArray(tags)) {
    const insertTag = db.prepare('INSERT INTO task_tags (id, task_id, name) VALUES (?, ?, ?)')
    for (const tag of tags.slice(0, 10)) {
      if (tag.trim()) insertTag.run(generateId(), id, tag.trim().slice(0, 30))
    }
  }

  return NextResponse.json({ id }, { status: 201 })
}
