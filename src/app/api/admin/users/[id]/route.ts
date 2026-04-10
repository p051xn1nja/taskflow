import { NextResponse } from 'next/server'
import { getDb, UPLOADS_PATH } from '@/lib/db'
import { requireAdmin } from '@/lib/api-helpers'
import { hash } from 'bcryptjs'
import { promises as fs } from 'fs'
import path from 'path'
import { z } from 'zod'

const UpdateUserSchema = z.object({
  display_name: z.string().trim().min(1).max(60).optional(),
  email: z.string().trim().toLowerCase().email().optional(),
  role: z.enum(['admin', 'user']).optional(),
  is_active: z.boolean().optional(),
  pending_approval: z.boolean().optional(),
  password: z.string().min(8).max(128).optional(),
})

export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAdmin()
  if (error) return error

  const db = getDb()
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(params.id) as { id: string; role: string } | undefined
  if (!user) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const parsed = UpdateUserSchema.safeParse(await req.json())
  if (!parsed.success) return NextResponse.json({ error: 'Invalid input' }, { status: 400 })
  const body = parsed.data
  const updates: string[] = []
  const values: (string | number)[] = []

  if (body.display_name !== undefined) { updates.push('display_name = ?'); values.push(body.display_name) }
  if (body.email !== undefined) { updates.push('email = ?'); values.push(body.email) }
  if (body.role !== undefined) {
    // Prevent removing the last admin
    if (body.role !== 'admin' && user.role === 'admin') {
      const adminCount = (db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin'").get() as { count: number }).count
      if (adminCount <= 1) {
        return NextResponse.json({ error: 'Cannot remove the last admin' }, { status: 400 })
      }
    }
    updates.push('role = ?')
    values.push(body.role)
  }
  if (body.is_active !== undefined) {
    // Prevent deactivating yourself
    if (params.id === session!.user.id && !body.is_active) {
      return NextResponse.json({ error: 'Cannot deactivate yourself' }, { status: 400 })
    }
    updates.push('is_active = ?')
    values.push(body.is_active ? 1 : 0)
  }
  if (body.pending_approval !== undefined) {
    updates.push('pending_approval = ?')
    values.push(body.pending_approval ? 1 : 0)
  }
  if (body.password) {
    const passwordHash = await hash(body.password, 12)
    updates.push('password_hash = ?')
    values.push(passwordHash)
  }

  if (updates.length > 0) {
    updates.push("updated_at = datetime('now')")
    values.push(params.id)
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values)
  }

  return NextResponse.json({ success: true })
}

export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAdmin()
  if (error) return error

  if (params.id === session!.user.id) {
    return NextResponse.json({ error: 'Cannot delete yourself' }, { status: 400 })
  }

  const db = getDb()

  // Delete profile photo file if exists
  const user = db.prepare('SELECT profile_photo FROM users WHERE id = ?').get(params.id) as { profile_photo: string } | undefined
  if (user?.profile_photo) {
    const photoPath = path.join(UPLOADS_PATH, user.profile_photo)
    try { await fs.unlink(photoPath) } catch {}
  }

  // Delete task attachment files
  const attachments = db.prepare(
    'SELECT a.filename FROM attachments a JOIN tasks t ON a.task_id = t.id WHERE t.user_id = ?'
  ).all(params.id) as { filename: string }[]
  for (const att of attachments) {
    const attPath = path.join(UPLOADS_PATH, att.filename)
    try { await fs.unlink(attPath) } catch {}
  }

  // Delete note attachment files
  const noteAttachments = db.prepare(
    'SELECT na.filename FROM note_attachments na JOIN notes n ON na.note_id = n.id WHERE n.user_id = ?'
  ).all(params.id) as { filename: string }[]
  for (const att of noteAttachments) {
    const attPath = path.join(UPLOADS_PATH, att.filename)
    try { await fs.unlink(attPath) } catch {}
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(params.id)
  return NextResponse.json({ success: true })
}
