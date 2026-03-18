import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAdmin } from '@/lib/api-helpers'

export async function GET() {
  const { error } = await requireAdmin()
  if (error) return error

  const db = getDb()
  const rows = db.prepare('SELECT key, value FROM platform_settings').all() as { key: string; value: string }[]
  const settings = Object.fromEntries(rows.map(r => [r.key, r.value]))

  return NextResponse.json(settings)
}

export async function PATCH(req: Request) {
  const { error } = await requireAdmin()
  if (error) return error

  const body = await req.json()
  const db = getDb()

  const upsert = db.prepare('INSERT OR REPLACE INTO platform_settings (key, value) VALUES (?, ?)')
  const allowedKeys = ['app_name', 'max_tasks_per_user', 'max_file_size_mb', 'allow_registration', 'max_categories_per_user', 'require_admin_approval']

  for (const [key, value] of Object.entries(body)) {
    if (allowedKeys.includes(key)) {
      upsert.run(key, String(value))
    }
  }

  return NextResponse.json({ success: true })
}
