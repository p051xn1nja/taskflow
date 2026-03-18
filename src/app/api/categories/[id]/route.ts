import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'

export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const cat = db.prepare('SELECT * FROM categories WHERE id = ? AND user_id = ?').get(params.id, session!.user.id)
  if (!cat) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const { name, color } = await req.json()
  const updates: string[] = []
  const values: string[] = []

  if (name !== undefined) { updates.push('name = ?'); values.push(name.trim()) }
  if (color !== undefined) { updates.push('color = ?'); values.push(color) }

  if (updates.length > 0) {
    values.push(params.id, session!.user.id)
    db.prepare(`UPDATE categories SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`).run(...values)
  }

  return NextResponse.json({ success: true })
}

export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  db.prepare('DELETE FROM categories WHERE id = ? AND user_id = ?').run(params.id, session!.user.id)
  return NextResponse.json({ success: true })
}
