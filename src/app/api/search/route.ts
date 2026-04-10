import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'

export async function GET(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const q = (new URL(req.url).searchParams.get('q') || '').trim()
  if (!q) return NextResponse.json({ tasks: [], notes: [] })

  const db = getDb()
  const userId = session!.user.id
  const like = `%${q}%`

  const tasks = db.prepare(
    `SELECT id, title, due_date, status, progress
     FROM tasks
     WHERE user_id = ? AND (title LIKE ? OR description LIKE ?)
     ORDER BY updated_at DESC
     LIMIT 8`
  ).all(userId, like, like)

  const notes = db.prepare(
    `SELECT id, title, updated_at
     FROM notes
     WHERE user_id = ? AND (title LIKE ? OR content LIKE ?)
     ORDER BY updated_at DESC
     LIMIT 8`
  ).all(userId, like, like)

  return NextResponse.json({ tasks, notes })
}
