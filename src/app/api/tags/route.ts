import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'

export async function GET(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const userId = session!.user.id

  const tags = db.prepare(`
    SELECT t.*,
      (SELECT COUNT(*) FROM task_tags tt WHERE tt.tag_id = t.id) as task_count,
      (SELECT COUNT(*) FROM note_tags nt WHERE nt.tag_id = t.id) as note_count
    FROM tags t
    WHERE t.user_id = ?
    ORDER BY t.name COLLATE NOCASE
  `).all(userId)

  return NextResponse.json(tags)
}

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const body = await req.json()
  const { name, color } = body

  if (!name || name.trim().length === 0) {
    return NextResponse.json({ error: 'Name is required' }, { status: 400 })
  }
  if (name.length > 30) {
    return NextResponse.json({ error: 'Name too long (max 30 characters)' }, { status: 400 })
  }

  const db = getDb()
  const userId = session!.user.id

  // Check for duplicate name
  const existing = db.prepare(
    'SELECT id FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE'
  ).get(userId, name.trim())

  if (existing) {
    return NextResponse.json({ error: 'A tag with this name already exists' }, { status: 409 })
  }

  const id = generateId()
  db.prepare(
    'INSERT INTO tags (id, user_id, name, color) VALUES (?, ?, ?, ?)'
  ).run(id, userId, name.trim(), color || '#3b82f6')

  return NextResponse.json({ id }, { status: 201 })
}
