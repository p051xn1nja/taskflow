import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { z } from 'zod'

const ReorderSchema = z.object({
  items: z.array(z.object({
    id: z.string().min(1),
    board_position: z.number().int().min(0).max(1_000_000),
  })).min(1).max(500),
})

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const parsed = ReorderSchema.safeParse(await req.json())
  if (!parsed.success) return NextResponse.json({ error: 'Invalid input' }, { status: 400 })
  const { items } = parsed.data

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
