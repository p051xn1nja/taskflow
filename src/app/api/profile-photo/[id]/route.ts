import { NextResponse } from 'next/server'
import { UPLOADS_PATH } from '@/lib/db'
import fs from 'fs'
import path from 'path'

const MIME_MAP: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
}

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  // Profile photos are served publicly (no auth required) so they can render in sidebar/avatars
  const filename = params.id
  const filePath = path.join(UPLOADS_PATH, filename)

  if (!fs.existsSync(filePath)) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  const ext = filename.split('.').pop()?.toLowerCase() || ''
  const mime = MIME_MAP[ext] || 'application/octet-stream'

  const buffer = fs.readFileSync(filePath)
  return new NextResponse(buffer, {
    headers: {
      'Content-Type': mime,
      'Cache-Control': 'public, max-age=3600',
    },
  })
}
