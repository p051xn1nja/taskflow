import { NextResponse } from 'next/server'
import { getDb, UPLOADS_PATH } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import { promises as fs } from 'fs'
import path from 'path'
import { z } from 'zod'

const ALLOWED_IMAGE_EXTENSIONS = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp'])
const MAX_PHOTO_SIZE = 5 * 1024 * 1024 // 5MB

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const formData = await req.formData()
  const file = formData.get('file') as File | null
  const userId = formData.get('user_id') as string | null

  // Allow admins to upload for other users, otherwise only self
  const targetUserId = userId && session!.user.role === 'admin' ? userId : session!.user.id

  if (!file) {
    return NextResponse.json({ error: 'No file provided' }, { status: 400 })
  }

  const ext = file.name.split('.').pop()?.toLowerCase() || ''
  if (!ALLOWED_IMAGE_EXTENSIONS.has(ext)) {
    return NextResponse.json({ error: 'Only image files are allowed (png, jpg, jpeg, gif, webp)' }, { status: 400 })
  }

  if (file.size > MAX_PHOTO_SIZE) {
    return NextResponse.json({ error: 'Photo must be under 5 MB' }, { status: 400 })
  }

  const db = getDb()

  // Delete old photo file if exists
  const user = db.prepare('SELECT profile_photo FROM users WHERE id = ?').get(targetUserId) as { profile_photo: string } | undefined
  if (!user) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 })
  }
  if (user.profile_photo) {
    const oldPath = path.join(UPLOADS_PATH, user.profile_photo)
    try { await fs.unlink(oldPath) } catch {}
  }

  const id = generateId()
  const filename = `profile_${id}.${ext}`
  const buffer = Buffer.from(await file.arrayBuffer())

  await fs.writeFile(path.join(UPLOADS_PATH, filename), buffer)

  db.prepare("UPDATE users SET profile_photo = ?, updated_at = datetime('now') WHERE id = ?").run(filename, targetUserId)

  return NextResponse.json({ filename, url: `/api/profile-photo/${filename}` }, { status: 201 })
}

export async function DELETE(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const body = await req.json().catch(() => ({}))
  const parsed = z.object({ user_id: z.string().min(1).optional() }).safeParse(body)
  const user_id = parsed.success ? parsed.data.user_id : undefined
  const targetUserId = user_id && session!.user.role === 'admin' ? user_id : session!.user.id

  const db = getDb()
  const user = db.prepare('SELECT profile_photo FROM users WHERE id = ?').get(targetUserId) as { profile_photo: string } | undefined
  if (!user) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 })
  }

  if (user.profile_photo) {
    const filePath = path.join(UPLOADS_PATH, user.profile_photo)
    try { await fs.unlink(filePath) } catch {}
    db.prepare("UPDATE users SET profile_photo = '', updated_at = datetime('now') WHERE id = ?").run(targetUserId)
  }

  return NextResponse.json({ success: true })
}
