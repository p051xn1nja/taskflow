import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const body = await req.json()
  const { items } = body as { items: { id: string; board_position: number }[] }

  if (!Array.isArray(items) || items.length === 0) {
    return NextResponse.json({ error: 'items array required' }, { status: 400 })
  }

  const db = getDb()
  const userId = session!.user.id

  const stmt = db.prepare('UPDATE tasks SET board_position = ? WHERE id = ? AND user_id = ?')
  const updateAll = db.transaction((rows: { id: string; board_position: number }[]) => {
    for (const row of rows) {
      stmt.run(row.board_position, row.id, userId)
    }
  })

  updateAll(items)

  return NextResponse.json({ success: true })
}
