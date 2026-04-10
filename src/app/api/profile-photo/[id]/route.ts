import { NextResponse } from 'next/server'
import { UPLOADS_PATH } from '@/lib/db'
import { promises as fs } from 'fs'
import path from 'path'
import { isSafeProfileFilename } from '@/lib/security'

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
  if (!isSafeProfileFilename(filename)) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }
  const filePath = path.join(UPLOADS_PATH, filename)

  try {
    await fs.access(filePath)
  } catch {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  const ext = filename.split('.').pop()?.toLowerCase() || ''
  const mime = MIME_MAP[ext] || 'application/octet-stream'

  const buffer = await fs.readFile(filePath)
  return new NextResponse(buffer, {
    headers: {
      'Content-Type': mime,
      'Cache-Control': 'public, max-age=3600',
      'X-Content-Type-Options': 'nosniff',
    },
  })
}
