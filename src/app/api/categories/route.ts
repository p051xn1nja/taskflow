import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import { getPlatformSettings } from '@/lib/platform-settings'

export async function GET() {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const categories = db.prepare(`
    SELECT c.*,
      COUNT(DISTINCT t.id) as task_count,
      COUNT(DISTINCT n.id) as note_count
    FROM categories c
    LEFT JOIN tasks t ON c.id = t.category_id
    LEFT JOIN notes n ON c.id = n.category_id
    WHERE c.user_id = ?
    GROUP BY c.id
    ORDER BY c.name ASC
  `).all(session!.user.id)

  return NextResponse.json(categories)
}

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const { name, color } = await req.json()

  if (!name || name.trim().length === 0) {
    return NextResponse.json({ error: 'Name is required' }, { status: 400 })
  }

  if (name.length > 40) {
    return NextResponse.json({ error: 'Name too long (max 40)' }, { status: 400 })
  }

  const db = getDb()
  const settings = getPlatformSettings(db)
  const categoryCount = db.prepare('SELECT COUNT(*) as count FROM categories WHERE user_id = ?').get(session!.user.id) as { count: number }
  if (categoryCount.count >= settings.maxCategoriesPerUser) {
    return NextResponse.json({ error: `Category limit reached (${settings.maxCategoriesPerUser})` }, { status: 400 })
  }

  const id = generateId()
  db.prepare('INSERT INTO categories (id, user_id, name, color) VALUES (?, ?, ?, ?)').run(
    id, session!.user.id, name.trim(), color || '#64748b'
  )

  return NextResponse.json({ id }, { status: 201 })
}
