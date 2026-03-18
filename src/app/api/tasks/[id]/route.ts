import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import fs from 'fs'
import path from 'path'
import { UPLOADS_PATH } from '@/lib/db'

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
    progress: 'progress',
    due_date: 'due_date',
  }

  for (const [key, col] of Object.entries(allowedFields)) {
    if (key in body) {
      updates.push(`${col} = ?`)
      values.push(body[key] === '' ? null : body[key])
    }
  }

  if (updates.length > 0) {
    updates.push("updated_at = datetime('now')")
    values.push(params.id, session!.user.id)
    db.prepare(`UPDATE tasks SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`).run(...values)
  }

  // Handle tags update — resolve names to master tag IDs
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

  // Delete attachment files
  const attachments = db.prepare('SELECT filename FROM attachments WHERE task_id = ?').all(params.id) as { filename: string }[]
  for (const att of attachments) {
    const filePath = path.join(UPLOADS_PATH, att.filename)
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath)
  }

  db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?').run(params.id, session!.user.id)
  return NextResponse.json({ success: true })
}
