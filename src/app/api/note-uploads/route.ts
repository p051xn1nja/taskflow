import { NextResponse } from 'next/server'
import { getDb, UPLOADS_PATH } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import { promises as fs } from 'fs'
import path from 'path'

const ALLOWED_EXTENSIONS = new Set([
  'pdf', 'txt', 'md', 'docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt',
  'csv', 'json', 'rtf', 'odt',
  'zip', 'rar', '7z', 'tar', 'gz',
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp',
])

const MAX_FILES_PER_NOTE = 10
const MAX_TOTAL_SIZE = 50 * 1024 * 1024 // 50MB total per note

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const formData = await req.formData()
  const noteId = formData.get('note_id') as string
  const files = formData.getAll('files') as File[]

  if (!noteId) return NextResponse.json({ error: 'note_id required' }, { status: 400 })

  const db = getDb()
  const note = db.prepare('SELECT id FROM notes WHERE id = ? AND user_id = ?').get(noteId, session!.user.id)
  if (!note) return NextResponse.json({ error: 'Note not found' }, { status: 404 })

  const existing = db.prepare(
    'SELECT COUNT(*) as count, COALESCE(SUM(size), 0) as total_size FROM note_attachments WHERE note_id = ?'
  ).get(noteId) as { count: number; total_size: number }

  if (existing.count + files.length > MAX_FILES_PER_NOTE) {
    return NextResponse.json({ error: `Max ${MAX_FILES_PER_NOTE} files per note` }, { status: 400 })
  }

  const newTotalSize = files.reduce((sum, f) => sum + f.size, 0)
  if (existing.total_size + newTotalSize > MAX_TOTAL_SIZE) {
    return NextResponse.json({ error: 'Total file size would exceed 50 MB limit' }, { status: 400 })
  }

  const uploaded = []
  for (const file of files) {
    const ext = file.name.split('.').pop()?.toLowerCase() || ''
    if (!ALLOWED_EXTENSIONS.has(ext)) continue

    const id = generateId()
    const filename = `${id}.${ext}`
    const buffer = Buffer.from(await file.arrayBuffer())

    await fs.writeFile(path.join(UPLOADS_PATH, filename), buffer)

    db.prepare(
      'INSERT INTO note_attachments (id, note_id, filename, original_name, mime_type, size) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(id, noteId, filename, file.name, file.type || 'application/octet-stream', file.size)

    uploaded.push({ id, filename, original_name: file.name, size: file.size })
  }

  return NextResponse.json({ uploaded }, { status: 201 })
}
