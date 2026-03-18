import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'

export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const userId = session!.user.id
  const status = db.prepare('SELECT * FROM statuses WHERE id = ? AND user_id = ?').get(
    params.id, userId
  ) as { id: string; is_default: number } | undefined

  if (!status) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const body = await req.json()
  const updates: string[] = []
  const values: (string | number | null)[] = []

  if ('name' in body && body.name?.trim()) {
    updates.push('name = ?')
    values.push(body.name.trim().slice(0, 40))
  }
  if ('color' in body && body.color) {
    updates.push('color = ?')
    values.push(body.color)
  }
  if ('is_completed' in body) {
    updates.push('is_completed = ?')
    values.push(body.is_completed ? 1 : 0)
  }
  if ('position' in body && typeof body.position === 'number') {
    updates.push('position = ?')
    values.push(body.position)
  }

  if (updates.length > 0) {
    values.push(params.id, userId)
    db.prepare(`UPDATE statuses SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`).run(...values)
  }

  // Handle reorder if positions array provided
  if ('positions' in body && Array.isArray(body.positions)) {
    const updatePos = db.prepare('UPDATE statuses SET position = ? WHERE id = ? AND user_id = ?')
    for (let i = 0; i < body.positions.length; i++) {
      updatePos.run(i, body.positions[i], userId)
    }
  }

  return NextResponse.json({ success: true })
}

export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const userId = session!.user.id
  const status = db.prepare('SELECT * FROM statuses WHERE id = ? AND user_id = ?').get(
    params.id, userId
  ) as { id: string; is_default: number } | undefined

  if (!status) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  // Cannot delete the default status
  if (status.is_default) {
    return NextResponse.json({ error: 'Cannot delete the default status' }, { status: 400 })
  }

  // Get the default status to reassign tasks
  const defaultStatus = db.prepare(
    'SELECT id FROM statuses WHERE user_id = ? AND is_default = 1'
  ).get(userId) as { id: string } | undefined

  if (!defaultStatus) {
    // Fallback: get first status by position that isn't the one being deleted
    const first = db.prepare(
      'SELECT id FROM statuses WHERE user_id = ? AND id != ? ORDER BY position LIMIT 1'
    ).get(userId, params.id) as { id: string } | undefined
    if (first) {
      db.prepare("UPDATE tasks SET status_id = ?, status = 'in_progress', progress = 0 WHERE status_id = ?").run(first.id, params.id)
    }
  } else {
    // Reassign tasks to default status, reset progress to 0
    db.prepare("UPDATE tasks SET status_id = ?, status = 'in_progress', progress = 0 WHERE status_id = ?").run(defaultStatus.id, params.id)
  }

  db.prepare('DELETE FROM statuses WHERE id = ? AND user_id = ?').run(params.id, userId)

  // Re-sequence positions
  const remaining = db.prepare(
    'SELECT id FROM statuses WHERE user_id = ? ORDER BY position'
  ).all(userId) as { id: string }[]
  const updatePos = db.prepare('UPDATE statuses SET position = ? WHERE id = ?')
  remaining.forEach((s, i) => updatePos.run(i, s.id))

  return NextResponse.json({ success: true })
}
