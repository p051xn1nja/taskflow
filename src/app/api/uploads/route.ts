import { NextResponse } from 'next/server'
import { getDb, UPLOADS_PATH } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { generateId } from '@/lib/utils'
import fs from 'fs'
import path from 'path'

const ALLOWED_EXTENSIONS = new Set([
  'pdf', 'txt', 'md', 'docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt',
  'csv', 'json', 'zip', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg',
])

const MAX_FILE_SIZE = 25 * 1024 * 1024

export async function POST(req: Request) {
  const { error, session } = await requireAuth()
  if (error) return error

  const formData = await req.formData()
  const taskId = formData.get('task_id') as string
  const files = formData.getAll('files') as File[]

  if (!taskId) return NextResponse.json({ error: 'task_id required' }, { status: 400 })

  const db = getDb()
  const task = db.prepare('SELECT id FROM tasks WHERE id = ? AND user_id = ?').get(taskId, session!.user.id)
  if (!task) return NextResponse.json({ error: 'Task not found' }, { status: 404 })

  const existingCount = (db.prepare('SELECT COUNT(*) as count FROM attachments WHERE task_id = ?').get(taskId) as { count: number }).count
  if (existingCount + files.length > 10) {
    return NextResponse.json({ error: 'Max 10 files per task' }, { status: 400 })
  }

  const uploaded = []
  for (const file of files) {
    const ext = file.name.split('.').pop()?.toLowerCase() || ''
    if (!ALLOWED_EXTENSIONS.has(ext)) continue
    if (file.size > MAX_FILE_SIZE) continue

    const id = generateId()
    const filename = `${id}.${ext}`
    const buffer = Buffer.from(await file.arrayBuffer())

    fs.writeFileSync(path.join(UPLOADS_PATH, filename), buffer)

    db.prepare(
      'INSERT INTO attachments (id, task_id, filename, original_name, mime_type, size) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(id, taskId, filename, file.name, file.type || 'application/octet-stream', file.size)

    uploaded.push({ id, filename, original_name: file.name, size: file.size })
  }

  return NextResponse.json({ uploaded }, { status: 201 })
}
