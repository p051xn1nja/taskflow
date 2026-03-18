import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'

export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const tag = db.prepare('SELECT * FROM tags WHERE id = ? AND user_id = ?').get(
    params.id, session!.user.id
  ) as { id: string; name: string } | undefined

  if (!tag) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const body = await req.json()
  const updates: string[] = []
  const values: (string | number | null)[] = []

  if ('name' in body && body.name?.trim()) {
    // Check for duplicate name (excluding current tag)
    const existing = db.prepare(
      'SELECT id FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE AND id != ?'
    ).get(session!.user.id, body.name.trim(), params.id)
    if (existing) {
      return NextResponse.json({ error: 'A tag with this name already exists' }, { status: 409 })
    }
    updates.push('name = ?')
    values.push(body.name.trim().slice(0, 30))
  }

  if ('color' in body && body.color) {
    updates.push('color = ?')
    values.push(body.color)
  }

  if (updates.length > 0) {
    values.push(params.id, session!.user.id)
    db.prepare(`UPDATE tags SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`).run(...values)
  }

  return NextResponse.json({ success: true })
}

export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const tag = db.prepare('SELECT id FROM tags WHERE id = ? AND user_id = ?').get(
    params.id, session!.user.id
  )
  if (!tag) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  // Cascading delete will remove task_tags and note_tags entries
  db.prepare('DELETE FROM tags WHERE id = ? AND user_id = ?').run(params.id, session!.user.id)
  return NextResponse.json({ success: true })
}
