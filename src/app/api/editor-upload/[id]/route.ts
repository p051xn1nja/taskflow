import { NextResponse } from 'next/server'
import { getDb, UPLOADS_PATH } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import { promises as fs } from 'fs'
import path from 'path'

const MIME_MAP: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  bmp: 'image/bmp',
}

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const upload = db.prepare(
    'SELECT filename FROM editor_uploads WHERE id = ? AND user_id = ?'
  ).get(params.id, session!.user.id) as { filename: string } | undefined
  if (!upload) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const filePath = path.join(UPLOADS_PATH, upload.filename)
  const ext = upload.filename.split('.').pop()?.toLowerCase() || ''
  const mime = MIME_MAP[ext] || 'application/octet-stream'

  const buffer = await fs.readFile(filePath)
  return new NextResponse(buffer, {
    headers: {
      'Content-Type': mime,
      'Cache-Control': 'public, max-age=31536000, immutable',
      'X-Content-Type-Options': 'nosniff',
    },
  })
}
