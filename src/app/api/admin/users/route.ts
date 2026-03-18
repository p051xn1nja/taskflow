import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAdmin } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import { hash } from 'bcryptjs'

export async function GET() {
  const { error } = await requireAdmin()
  if (error) return error

  const db = getDb()
  const users = db.prepare(`
    SELECT u.id, u.username, u.email, u.display_name, u.role, u.is_active, u.pending_approval, u.created_at, u.updated_at,
      COUNT(t.id) as task_count
    FROM users u
    LEFT JOIN tasks t ON u.id = t.user_id
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `).all()

  return NextResponse.json(users)
}

export async function POST(req: Request) {
  const { error } = await requireAdmin()
  if (error) return error

  const { username, email, password, display_name, role } = await req.json()

  if (!username || !email || !password) {
    return NextResponse.json({ error: 'All fields are required' }, { status: 400 })
  }

  const db = getDb()
  const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email)
  if (existing) {
    return NextResponse.json({ error: 'Username or email already exists' }, { status: 409 })
  }

  const id = generateId()
  const passwordHash = await hash(password, 12)
  db.prepare(
    'INSERT INTO users (id, username, email, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(id, username, email, passwordHash, display_name || username, role || 'user')

  return NextResponse.json({ id }, { status: 201 })
}
