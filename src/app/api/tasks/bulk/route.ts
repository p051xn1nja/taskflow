import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { z } from 'zod'

const BulkSchema = z.object({
  task_ids: z.array(z.string().min(1)).min(1).max(500),
  action: z.enum(['complete', 'delete']),
})

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const parsed = BulkSchema.safeParse(await req.json())
  if (!parsed.success) return NextResponse.json({ error: 'Invalid input' }, { status: 400 })

  const db = getDb()
  const userId = session!.user.id
  const { task_ids, action } = parsed.data

  const placeholders = task_ids.map(() => '?').join(',')
  const ownedIds = db.prepare(`SELECT id FROM tasks WHERE user_id = ? AND id IN (${placeholders})`).all(userId, ...task_ids) as { id: string }[]
  if (ownedIds.length === 0) return NextResponse.json({ updated: 0 })

  const ids = ownedIds.map(r => r.id)
  const idPlaceholders = ids.map(() => '?').join(',')

  if (action === 'complete') {
    const completedStatus = db.prepare('SELECT id FROM statuses WHERE user_id = ? AND is_completed = 1 LIMIT 1').get(userId) as { id: string } | undefined
    const stmt = db.prepare(`UPDATE tasks SET status = 'completed', status_id = ?, progress = 100, updated_at = datetime('now') WHERE user_id = ? AND id IN (${idPlaceholders})`)
    stmt.run(completedStatus?.id || null, userId, ...ids)
    return NextResponse.json({ updated: ids.length })
  }

  const stmt = db.prepare(`DELETE FROM tasks WHERE user_id = ? AND id IN (${idPlaceholders})`)
  stmt.run(userId, ...ids)
  return NextResponse.json({ deleted: ids.length })
}
