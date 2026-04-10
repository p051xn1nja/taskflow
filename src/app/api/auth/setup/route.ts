import { NextResponse } from 'next/server'
import { hash } from 'bcryptjs'
import { getDb } from '@/lib/db'
import { generateId } from '@/lib/utils'
import { z } from 'zod'
import { checkRateLimit, getClientIdentifier } from '@/lib/security'

const SetupSchema = z.object({
  username: z.string().trim().min(3).max(30),
  email: z.string().trim().toLowerCase().email(),
  password: z.string().min(8).max(128),
  display_name: z.string().trim().min(1).max(60).optional(),
})

export async function GET() {
  const db = getDb()
  const count = db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number }
  return NextResponse.json({ hasUsers: count.count > 0 })
}

export async function POST(req: Request) {
  const identifier = getClientIdentifier(req)
  const rl = checkRateLimit(`setup:${identifier}`, { limit: 6, windowMs: 60_000 })
  if (!rl.allowed) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 })
  }

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

  const parsed = SetupSchema.safeParse(await req.json())
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid input' }, { status: 400 })
  }

  const { username, email, password, display_name } = parsed.data

  // Check for existing user
  const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email)
  if (existing) {
    return NextResponse.json({ error: 'Username or email already exists' }, { status: 409 })
  }

  const passwordHash = await hash(password, 12)
  const id = generateId()

  // Check if admin approval is required for new registrations
  let needsApproval = false
  if (!isFirstUser) {
    const approvalSetting = db.prepare("SELECT value FROM platform_settings WHERE key = 'require_admin_approval'").get() as { value: string } | undefined
    needsApproval = approvalSetting?.value === 'true'
  }

  db.prepare(
    'INSERT INTO users (id, username, email, password_hash, display_name, role, is_active, pending_approval) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(id, username, email, passwordHash, display_name || username, isFirstUser ? 'admin' : 'user', needsApproval ? 0 : 1, needsApproval ? 1 : 0)

  if (needsApproval) {
    return NextResponse.json({ success: true, pending_approval: true })
  }

  return NextResponse.json({ success: true, role: isFirstUser ? 'admin' : 'user' })
}
