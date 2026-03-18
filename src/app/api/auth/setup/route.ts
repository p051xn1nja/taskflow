import { NextResponse } from 'next/server'
import { hash } from 'bcryptjs'
import { getDb } from '@/lib/db'
import { generateId } from '@/lib/utils'

export async function GET() {
  const db = getDb()
  const count = db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number }
  return NextResponse.json({ hasUsers: count.count > 0 })
}

export async function POST(req: Request) {
  const db = getDb()
  const count = db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number }

  // If users already exist, check if registration is allowed
  const isFirstUser = count.count === 0
  if (!isFirstUser) {
    const setting = db.prepare("SELECT value FROM platform_settings WHERE key = 'allow_registration'").get() as { value: string } | undefined
    if (setting?.value !== 'true') {
      return NextResponse.json({ error: 'Registration is disabled' }, { status: 403 })
    }
  }

  const body = await req.json()
  const { username, email, password, display_name } = body

  if (!username || !email || !password) {
    return NextResponse.json({ error: 'All fields are required' }, { status: 400 })
  }

  if (username.length < 3 || username.length > 30) {
    return NextResponse.json({ error: 'Username must be 3-30 characters' }, { status: 400 })
  }

  if (password.length < 8) {
    return NextResponse.json({ error: 'Password must be at least 8 characters' }, { status: 400 })
  }

  // Check for existing user
  const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email)
  if (existing) {
    return NextResponse.json({ error: 'Username or email already exists' }, { status: 409 })
  }

  const passwordHash = await hash(password, 12)
  const id = generateId()

  db.prepare(
    'INSERT INTO users (id, username, email, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(id, username, email, passwordHash, display_name || username, isFirstUser ? 'admin' : 'user')

  return NextResponse.json({ success: true, role: isFirstUser ? 'admin' : 'user' })
}
