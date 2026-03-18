import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'

export async function GET(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const url = new URL(req.url)
  const search = url.searchParams.get('search') || ''
  const tag = url.searchParams.get('tag') || ''
  const page = Math.max(1, parseInt(url.searchParams.get('page') || '1'))
  const perPage = Math.min(200, Math.max(1, parseInt(url.searchParams.get('per_page') || '50')))

  const db = getDb()
  const userId = session!.user.id

  let where = 'WHERE n.user_id = ?'
  const params: (string | number)[] = [userId]

  if (search) {
    where += ' AND (n.title LIKE ? OR n.content LIKE ?)'
    params.push(`%${search}%`, `%${search}%`)
  }
  if (tag) {
    where += ' AND n.id IN (SELECT nt.note_id FROM note_tags nt JOIN tags tg ON nt.tag_id = tg.id WHERE tg.name = ?)'
    params.push(tag)
  }

  const countRow = db.prepare(`SELECT COUNT(*) as total FROM notes n ${where}`).get(...params) as { total: number }
  const total = countRow.total
  const totalPages = Math.ceil(total / perPage)
  const offset = (page - 1) * perPage

  const notes = db.prepare(`
    SELECT n.*
    FROM notes n
    ${where}
    ORDER BY n.updated_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, perPage, offset) as { id: string; title: string; content: string; created_at: string; updated_at: string }[]

  const getTagsStmt = db.prepare(`
    SELECT tg.id, tg.name, tg.color
    FROM note_tags nt
    JOIN tags tg ON nt.tag_id = tg.id
    WHERE nt.note_id = ?
  `)
  const getAttachmentsStmt = db.prepare('SELECT * FROM note_attachments WHERE note_id = ?')
  const getLinkedTasksStmt = db.prepare(`
    SELECT t.id, t.title, t.status, t.progress
    FROM note_tasks ntl
    JOIN tasks t ON ntl.task_id = t.id
    WHERE ntl.note_id = ?
  `)

  const enrichedNotes = notes.map(note => ({
    ...note,
    tags: getTagsStmt.all(note.id),
    attachments: getAttachmentsStmt.all(note.id),
    linked_tasks: getLinkedTasksStmt.all(note.id),
  }))

  return NextResponse.json({
    notes: enrichedNotes,
    pagination: { page, per_page: perPage, total, total_pages: totalPages },
  })
}

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const body = await req.json()
  const { title, content, tags, linked_task_ids } = body

  if (!title || title.trim().length === 0) {
    return NextResponse.json({ error: 'Title is required' }, { status: 400 })
  }
  if (title.length > 200) {
    return NextResponse.json({ error: 'Title too long' }, { status: 400 })
  }

  const db = getDb()
  const id = generateId()
  const userId = session!.user.id

  db.prepare(
    'INSERT INTO notes (id, user_id, title, content) VALUES (?, ?, ?, ?)'
  ).run(id, userId, title.trim(), (content || '').trim())

  // Insert tags
  if (tags && Array.isArray(tags)) {
    const findTag = db.prepare('SELECT id FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE')
    const insertTag = db.prepare('INSERT INTO tags (id, user_id, name, color) VALUES (?, ?, ?, ?)')
    const insertNoteTag = db.prepare('INSERT INTO note_tags (id, note_id, tag_id) VALUES (?, ?, ?)')

    for (const tagName of tags.slice(0, 10)) {
      const trimmed = typeof tagName === 'string' ? tagName.trim().slice(0, 30) : ''
      if (!trimmed) continue

      let tagRow = findTag.get(userId, trimmed) as { id: string } | undefined
      if (!tagRow) {
        const newTagId = generateId()
        insertTag.run(newTagId, userId, trimmed, '#3b82f6')
        tagRow = { id: newTagId }
      }

      insertNoteTag.run(generateId(), id, tagRow.id)
    }
  }

  // Link tasks
  if (linked_task_ids && Array.isArray(linked_task_ids)) {
    const insertLink = db.prepare('INSERT INTO note_tasks (id, note_id, task_id) VALUES (?, ?, ?)')
    const checkTask = db.prepare('SELECT id FROM tasks WHERE id = ? AND user_id = ?')
    for (const taskId of linked_task_ids) {
      if (checkTask.get(taskId, userId)) {
        insertLink.run(generateId(), id, taskId)
      }
    }
  }

  return NextResponse.json({ id }, { status: 201 })
}
