import { NextResponse } from 'next/server'
import { getDb, UPLOADS_PATH } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import fs from 'fs'
import path from 'path'

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const note = db.prepare(`
    SELECT n.*, c.name as category_name, c.color as category_color
    FROM notes n
    LEFT JOIN categories c ON n.category_id = c.id
    WHERE n.id = ? AND n.user_id = ?
  `).get(
    params.id, session!.user.id
  ) as { id: string; title: string; content: string; category_id: string | null; category_name: string | null; category_color: string | null; created_at: string; updated_at: string } | undefined

  if (!note) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const tags = db.prepare(`
    SELECT tg.id, tg.name, tg.color
    FROM note_tags nt
    JOIN tags tg ON nt.tag_id = tg.id
    WHERE nt.note_id = ?
  `).all(params.id)

  const attachments = db.prepare('SELECT * FROM note_attachments WHERE note_id = ?').all(params.id)

  const linked_tasks = db.prepare(`
    SELECT t.id, t.title, t.status, t.progress
    FROM note_tasks ntl
    JOIN tasks t ON ntl.task_id = t.id
    WHERE ntl.note_id = ?
  `).all(params.id)

  return NextResponse.json({
    ...note,
    category: note.category_id ? { id: note.category_id, name: note.category_name, color: note.category_color } : null,
    tags,
    attachments,
    linked_tasks,
  })
}

export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const userId = session!.user.id
  const note = db.prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?').get(
    params.id, userId
  )
  if (!note) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const body = await req.json()
  const updates: string[] = []
  const values: (string | null)[] = []

  if ('title' in body && body.title?.trim()) {
    updates.push('title = ?')
    values.push(body.title.trim().slice(0, 200))
  }
  if ('content' in body) {
    updates.push('content = ?')
    values.push(body.content || '')
  }
  if ('color' in body) {
    updates.push('color = ?')
    values.push(body.color || '')
  }
  if ('category_id' in body) {
    updates.push('category_id = ?')
    values.push(body.category_id || null)
  }

  if (updates.length > 0) {
    updates.push("updated_at = datetime('now')")
    values.push(params.id, userId)
    db.prepare(`UPDATE notes SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`).run(...values)
  }

  // Handle tags
  if ('tags' in body && Array.isArray(body.tags)) {
    db.prepare('DELETE FROM note_tags WHERE note_id = ?').run(params.id)

    const findTag = db.prepare('SELECT id FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE')
    const insertTag = db.prepare('INSERT INTO tags (id, user_id, name, color) VALUES (?, ?, ?, ?)')
    const insertNoteTag = db.prepare('INSERT INTO note_tags (id, note_id, tag_id) VALUES (?, ?, ?)')

    for (const tagName of body.tags.slice(0, 10)) {
      const trimmed = typeof tagName === 'string' ? tagName.trim().slice(0, 30) : ''
      if (!trimmed) continue

      let tagRow = findTag.get(userId, trimmed) as { id: string } | undefined
      if (!tagRow) {
        const newTagId = generateId()
        insertTag.run(newTagId, userId, trimmed, '#3b82f6')
        tagRow = { id: newTagId }
      }

      insertNoteTag.run(generateId(), params.id, tagRow.id)
    }
  }

  // Handle linked tasks
  if ('linked_task_ids' in body && Array.isArray(body.linked_task_ids)) {
    db.prepare('DELETE FROM note_tasks WHERE note_id = ?').run(params.id)
    const insertLink = db.prepare('INSERT INTO note_tasks (id, note_id, task_id) VALUES (?, ?, ?)')
    const checkTask = db.prepare('SELECT id FROM tasks WHERE id = ? AND user_id = ?')
    for (const taskId of body.linked_task_ids) {
      if (checkTask.get(taskId, userId)) {
        insertLink.run(generateId(), params.id, taskId)
      }
    }
  }

  return NextResponse.json({ success: true })
}

export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const note = db.prepare('SELECT id FROM notes WHERE id = ? AND user_id = ?').get(
    params.id, session!.user.id
  )
  if (!note) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  // Delete attachment files
  const attachments = db.prepare('SELECT filename FROM note_attachments WHERE note_id = ?').all(params.id) as { filename: string }[]
  for (const att of attachments) {
    const filePath = path.join(UPLOADS_PATH, att.filename)
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath)
  }

  db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?').run(params.id, session!.user.id)
  return NextResponse.json({ success: true })
}
