import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import { z } from 'zod'

const TemplateSchema = z.object({
  name: z.string().trim().min(1).max(40),
  title: z.string().trim().min(1).max(120),
  description: z.string().max(2000).optional(),
  category_id: z.string().optional().nullable(),
  tags: z.array(z.string()).max(10).optional(),
  recurrence: z.enum(['none', 'daily', 'weekly', 'monthly']).optional(),
})

export async function GET() {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const rows = db.prepare('SELECT * FROM task_templates WHERE user_id = ? ORDER BY created_at DESC').all(session!.user.id) as (Record<string, unknown> & { tags_json: string })[]
  return NextResponse.json(rows.map(r => ({ ...r, tags: JSON.parse(r.tags_json || '[]') })))
}

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const parsed = TemplateSchema.safeParse(await req.json())
  if (!parsed.success) return NextResponse.json({ error: 'Invalid input' }, { status: 400 })

  const db = getDb()
  const count = db.prepare('SELECT COUNT(*) as c FROM task_templates WHERE user_id = ?').get(session!.user.id) as { c: number }
  if (count.c >= 30) return NextResponse.json({ error: 'Max 30 templates' }, { status: 400 })

  const id = generateId()
  db.prepare(`
    INSERT INTO task_templates (id, user_id, name, title, description, category_id, tags_json, recurrence)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    session!.user.id,
    parsed.data.name,
    parsed.data.title,
    parsed.data.description || '',
    parsed.data.category_id || null,
    JSON.stringify(parsed.data.tags || []),
    parsed.data.recurrence || 'none',
  )

  return NextResponse.json({ id }, { status: 201 })
}
