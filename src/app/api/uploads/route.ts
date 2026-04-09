import { NextResponse } from 'next/server'
import { getDb, UPLOADS_PATH } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import { promises as fs } from 'fs'
import path from 'path'
import { getPlatformSettings } from '@/lib/platform-settings'

const ALLOWED_EXTENSIONS = new Set([
  'pdf', 'txt', 'md', 'docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt',
  'csv', 'json', 'rtf', 'odt',
  'zip', 'rar', '7z', 'tar', 'gz',
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp',
])

const MAX_FILES_PER_TASK = 10
const MIME_BY_EXTENSION: Record<string, string[]> = {
  pdf: ['application/pdf'],
  txt: ['text/plain'],
  md: ['text/markdown', 'text/plain'],
  docx: ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  doc: ['application/msword'],
  xlsx: ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
  xls: ['application/vnd.ms-excel'],
  pptx: ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
  ppt: ['application/vnd.ms-powerpoint'],
  csv: ['text/csv', 'application/vnd.ms-excel', 'text/plain'],
  json: ['application/json', 'text/json', 'text/plain'],
  rtf: ['application/rtf', 'text/rtf'],
  odt: ['application/vnd.oasis.opendocument.text'],
  zip: ['application/zip', 'application/x-zip-compressed'],
  rar: ['application/vnd.rar', 'application/x-rar-compressed'],
  '7z': ['application/x-7z-compressed'],
  tar: ['application/x-tar'],
  gz: ['application/gzip', 'application/x-gzip'],
  png: ['image/png'],
  jpg: ['image/jpeg'],
  jpeg: ['image/jpeg'],
  gif: ['image/gif'],
  webp: ['image/webp'],
  bmp: ['image/bmp'],
}

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const formData = await req.formData()
  const taskId = formData.get('task_id') as string
  const files = formData.getAll('files') as File[]

  if (!taskId) return NextResponse.json({ error: 'task_id required' }, { status: 400 })

  const db = getDb()
  const settings = getPlatformSettings(db)
  const maxTotalSize = settings.maxFileSizeMb * 1024 * 1024

  const task = db.prepare('SELECT id FROM tasks WHERE id = ? AND user_id = ?').get(taskId, session!.user.id)
  if (!task) return NextResponse.json({ error: 'Task not found' }, { status: 404 })

  const existing = db.prepare(
    'SELECT COUNT(*) as count, COALESCE(SUM(size), 0) as total_size FROM attachments WHERE task_id = ?'
  ).get(taskId) as { count: number; total_size: number }

  if (existing.count + files.length > MAX_FILES_PER_TASK) {
    return NextResponse.json({ error: `Max ${MAX_FILES_PER_TASK} files per task` }, { status: 400 })
  }

  const newTotalSize = files.reduce((sum, f) => sum + f.size, 0)
  if (existing.total_size + newTotalSize > maxTotalSize) {
    return NextResponse.json({ error: `Total file size would exceed ${settings.maxFileSizeMb} MB limit` }, { status: 400 })
  }

  const uploaded = []
  for (const file of files) {
    const ext = file.name.split('.').pop()?.toLowerCase() || ''
    if (!ALLOWED_EXTENSIONS.has(ext)) continue
    const allowedMimes = MIME_BY_EXTENSION[ext]
    if (allowedMimes && file.type && !allowedMimes.includes(file.type)) continue

    const id = generateId()
    const filename = `${id}.${ext}`
    const buffer = Buffer.from(await file.arrayBuffer())

    await fs.writeFile(path.join(UPLOADS_PATH, filename), buffer)

    db.prepare(
      'INSERT INTO attachments (id, task_id, filename, original_name, mime_type, size) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(id, taskId, filename, file.name, file.type || 'application/octet-stream', file.size)

    uploaded.push({ id, filename, original_name: file.name, size: file.size })
  }

  return NextResponse.json({ uploaded }, { status: 201 })
}
