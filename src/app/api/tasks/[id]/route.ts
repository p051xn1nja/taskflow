import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import fs from 'fs'
import path from 'path'
import { UPLOADS_PATH } from '@/lib/db'

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const task = db.prepare(`
    SELECT t.*, c.name as category_name, c.color as category_color,
      s.name as status_name, s.color as status_color, s.is_completed as status_is_completed, s.is_default as status_is_default, s.position as status_position
    FROM tasks t
    LEFT JOIN categories c ON t.category_id = c.id
    LEFT JOIN statuses s ON t.status_id = s.id
    WHERE t.id = ? AND t.user_id = ?
  `).get(params.id, session!.user.id) as Record<string, unknown> | undefined
  if (!task) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const tags = db.prepare(`
    SELECT tg.id, tg.name, tg.color
    FROM task_tags tt JOIN tags tg ON tt.tag_id = tg.id
    WHERE tt.task_id = ?
  `).all(params.id)

  const attachments = db.prepare('SELECT * FROM attachments WHERE task_id = ?').all(params.id)

  return NextResponse.json({
    ...task,
    tags,
    attachments,
    category: task.category_id ? { id: task.category_id, name: task.category_name, color: task.category_color } : null,
    task_status: task.status_id ? {
      id: task.status_id,
      name: task.status_name,
      color: task.status_color,
      is_completed: task.status_is_completed === 1,
      is_default: task.status_is_default === 1,
      position: task.status_position ?? 0,
    } : null,
  })
}

export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const task = db.prepare('SELECT * FROM tasks WHERE id = ? AND user_id = ?').get(params.id, session!.user.id) as { id: string } | undefined
  if (!task) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const body = await req.json()
  const updates: string[] = []
  const values: (string | number | null)[] = []

  const allowedFields: Record<string, string> = {
    title: 'title',
    description: 'description',
    category_id: 'category_id',
    status: 'status',
    status_id: 'status_id',
    progress: 'progress',
    start_date: 'start_date',
    due_date: 'due_date',
    board_position: 'board_position',
  }

  // Fields where empty string should become null (nullable fields)
  const nullableFields = new Set(['category_id', 'status_id', 'start_date', 'due_date'])

  for (const [key, col] of Object.entries(allowedFields)) {
    if (key in body) {
      updates.push(`${col} = ?`)
      values.push(nullableFields.has(key) && body[key] === '' ? null : body[key])
    }
  }

  // If status_id changed, sync the legacy status column
  if ('status_id' in body && body.status_id) {
    const newStatus = db.prepare('SELECT is_completed FROM statuses WHERE id = ?').get(body.status_id) as { is_completed: number } | undefined
    if (newStatus) {
      // Only update legacy status if not already being set
      if (!('status' in body)) {
        updates.push('status = ?')
        values.push(newStatus.is_completed ? 'completed' : 'in_progress')
      }
    }
  }

  // If legacy status is set without status_id, resolve status_id automatically
  if ('status' in body && !('status_id' in body)) {
    if (body.status === 'completed') {
      const completedStatus = db.prepare('SELECT id FROM statuses WHERE user_id = ? AND is_completed = 1').get(session!.user.id) as { id: string } | undefined
      if (completedStatus) {
        updates.push('status_id = ?')
        values.push(completedStatus.id)
      }
    } else if (body.status === 'in_progress') {
      // Find the "In Progress" status (non-default, non-completed)
      const inProgressStatus = db.prepare('SELECT id FROM statuses WHERE user_id = ? AND is_default = 0 AND is_completed = 0 ORDER BY position LIMIT 1').get(session!.user.id) as { id: string } | undefined
      if (inProgressStatus) {
        updates.push('status_id = ?')
        values.push(inProgressStatus.id)
      }
    }
  }

  // Auto-move to "In Progress" when progress is set to 1-99% (and no explicit status change)
  if ('progress' in body && !('status' in body) && !('status_id' in body)) {
    const progress = Number(body.progress)
    if (progress >= 1 && progress <= 99) {
      const inProgressStatus = db.prepare('SELECT id FROM statuses WHERE user_id = ? AND is_default = 0 AND is_completed = 0 ORDER BY position LIMIT 1').get(session!.user.id) as { id: string } | undefined
      if (inProgressStatus) {
        updates.push('status_id = ?')
        values.push(inProgressStatus.id)
        updates.push('status = ?')
        values.push('in_progress')
      }
    }
  }

  if (updates.length > 0) {
    updates.push("updated_at = datetime('now')")
    values.push(params.id, session!.user.id)
    db.prepare(`UPDATE tasks SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`).run(...values)
  }

  // Handle tags update
  if ('tags' in body && Array.isArray(body.tags)) {
    const userId = session!.user.id
    db.prepare('DELETE FROM task_tags WHERE task_id = ?').run(params.id)

    const findTag = db.prepare('SELECT id FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE')
    const insertTag = db.prepare('INSERT INTO tags (id, user_id, name, color) VALUES (?, ?, ?, ?)')
    const insertTaskTag = db.prepare('INSERT INTO task_tags (id, task_id, tag_id) VALUES (?, ?, ?)')

    for (const tagName of body.tags.slice(0, 10)) {
      const trimmed = typeof tagName === 'string' ? tagName.trim().slice(0, 30) : ''
      if (!trimmed) continue

      let tagRow = findTag.get(userId, trimmed) as { id: string } | undefined
      if (!tagRow) {
        const newTagId = generateId()
        insertTag.run(newTagId, userId, trimmed, '#3b82f6')
        tagRow = { id: newTagId }
      }

      insertTaskTag.run(generateId(), params.id, tagRow.id)
    }
  }

  return NextResponse.json({ success: true })
}

export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const task = db.prepare('SELECT * FROM tasks WHERE id = ? AND user_id = ?').get(params.id, session!.user.id)
  if (!task) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const attachments = db.prepare('SELECT filename FROM attachments WHERE task_id = ?').all(params.id) as { filename: string }[]
  for (const att of attachments) {
    const filePath = path.join(UPLOADS_PATH, att.filename)
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath)
  }

  db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?').run(params.id, session!.user.id)
  return NextResponse.json({ success: true })
}
