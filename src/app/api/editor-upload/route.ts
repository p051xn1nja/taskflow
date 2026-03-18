import { NextResponse } from 'next/server'
import { getDb, UPLOADS_PATH } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import fs from 'fs'
import path from 'path'

const IMAGE_EXTENSIONS = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp'])

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const formData = await req.formData()
  const file = formData.get('file') as File
  const noteId = formData.get('note_id') as string | null

  if (!file) return NextResponse.json({ error: 'No file provided' }, { status: 400 })

  const ext = file.name.split('.').pop()?.toLowerCase() || ''
  if (!IMAGE_EXTENSIONS.has(ext)) {
    return NextResponse.json({ error: 'Only image files allowed' }, { status: 400 })
  }

  if (file.size > 10 * 1024 * 1024) {
    return NextResponse.json({ error: 'Image must be under 10 MB' }, { status: 400 })
  }

  const id = generateId()
  const filename = `${id}.${ext}`
  const buffer = Buffer.from(await file.arrayBuffer())

  fs.writeFileSync(path.join(UPLOADS_PATH, filename), buffer)

  // If note_id provided, track as note attachment
  if (noteId) {
    const db = getDb()
    const note = db.prepare('SELECT id FROM notes WHERE id = ? AND user_id = ?').get(noteId, session!.user.id)
    if (note) {
      db.prepare(
        'INSERT INTO note_attachments (id, note_id, filename, original_name, mime_type, size) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(id, noteId, filename, file.name, file.type || 'application/octet-stream', file.size)
    }
  }

  return NextResponse.json({
    url: `/api/editor-upload/${id}`,
    id,
  })
}
