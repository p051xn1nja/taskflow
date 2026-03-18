import { NextResponse } from 'next/server'
import { getDb, ensureDefaultStatuses } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'

export async function GET(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const userId = session!.user.id

  ensureDefaultStatuses(db, userId)

  const statuses = db.prepare(`
    SELECT s.*,
      (SELECT COUNT(*) FROM tasks t WHERE t.status_id = s.id) as task_count
    FROM statuses s
    WHERE s.user_id = ?
    ORDER BY s.position ASC
  `).all(userId)

  return NextResponse.json(statuses)
}

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const body = await req.json()
  const { name, color, is_completed } = body

  if (!name || name.trim().length === 0) {
    return NextResponse.json({ error: 'Name is required' }, { status: 400 })
  }
  if (name.length > 40) {
    return NextResponse.json({ error: 'Name too long' }, { status: 400 })
  }

  const db = getDb()
  const userId = session!.user.id

  // Get next position
  const maxPos = db.prepare(
    'SELECT COALESCE(MAX(position), -1) as max_pos FROM statuses WHERE user_id = ?'
  ).get(userId) as { max_pos: number }

  const id = generateId()
  db.prepare(
    'INSERT INTO statuses (id, user_id, name, color, position, is_completed, is_default) VALUES (?, ?, ?, ?, ?, ?, 0)'
  ).run(id, userId, name.trim(), color || '#3b82f6', maxPos.max_pos + 1, is_completed ? 1 : 0)

  return NextResponse.json({ id }, { status: 201 })
}
