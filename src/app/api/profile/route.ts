import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { hash, compare } from 'bcryptjs'

export async function GET() {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const user = db.prepare(
    'SELECT id, username, email, display_name, role, profile_photo, created_at FROM users WHERE id = ?'
  ).get(session!.user.id) as {
    id: string; username: string; email: string; display_name: string
    role: string; profile_photo: string; created_at: string
  } | undefined

  if (!user) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  return NextResponse.json(user)
}

export async function PATCH(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const userId = session!.user.id
  const body = await req.json()

  const updates: string[] = []
  const values: (string | number)[] = []

  if (body.display_name !== undefined) {
    const name = body.display_name.trim().slice(0, 100)
    updates.push('display_name = ?')
    values.push(name)
  }

  if (body.email !== undefined) {
    const email = body.email.trim().toLowerCase()
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return NextResponse.json({ error: 'Invalid email address' }, { status: 400 })
    }
    // Check uniqueness
    const existing = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(email, userId)
    if (existing) {
      return NextResponse.json({ error: 'Email already in use' }, { status: 400 })
    }
    updates.push('email = ?')
    values.push(email)
  }

  if (body.new_password) {
    if (body.new_password.length < 6) {
      return NextResponse.json({ error: 'Password must be at least 6 characters' }, { status: 400 })
    }
    // Verify current password
    if (!body.current_password) {
      return NextResponse.json({ error: 'Current password is required' }, { status: 400 })
    }
    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(userId) as { password_hash: string }
    const valid = await compare(body.current_password, user.password_hash)
    if (!valid) {
      return NextResponse.json({ error: 'Current password is incorrect' }, { status: 400 })
    }
    const passwordHash = await hash(body.new_password, 12)
    updates.push('password_hash = ?')
    values.push(passwordHash)
  }

  if (updates.length === 0) {
    return NextResponse.json({ error: 'No changes provided' }, { status: 400 })
  }

  updates.push("updated_at = datetime('now')")
  values.push(userId)
  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values)

  return NextResponse.json({ success: true })
}
