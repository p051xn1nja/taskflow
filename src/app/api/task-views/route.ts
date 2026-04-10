import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import { z } from 'zod'

const CreateViewSchema = z.object({
  name: z.string().trim().min(1).max(40),
  filters: z.object({
    search: z.string().optional(),
    category_id: z.string().optional(),
    status_id: z.string().optional(),
    tag: z.string().optional(),
    date_from: z.string().optional(),
    date_to: z.string().optional(),
    view: z.enum(['all', 'inbox', 'today', 'upcoming']).optional(),
  }).strict(),
})

export async function GET() {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const views = db.prepare(
    'SELECT id, user_id, name, filters_json, created_at FROM task_views WHERE user_id = ? ORDER BY created_at DESC'
  ).all(session!.user.id)

  return NextResponse.json(views)
}

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const parsed = CreateViewSchema.safeParse(await req.json())
  if (!parsed.success) return NextResponse.json({ error: 'Invalid input' }, { status: 400 })

  const db = getDb()
  const count = db.prepare('SELECT COUNT(*) as c FROM task_views WHERE user_id = ?').get(session!.user.id) as { c: number }
  if (count.c >= 20) return NextResponse.json({ error: 'Max 20 saved views' }, { status: 400 })

  const id = generateId()
  db.prepare(
    'INSERT INTO task_views (id, user_id, name, filters_json) VALUES (?, ?, ?, ?)'
  ).run(id, session!.user.id, parsed.data.name, JSON.stringify(parsed.data.filters))

  return NextResponse.json({ id }, { status: 201 })
}
