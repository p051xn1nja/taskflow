import { NextResponse } from 'next/server'
import { UPLOADS_PATH } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import fs from 'fs'
import path from 'path'

const MIME_MAP: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  svg: 'image/svg+xml',
  bmp: 'image/bmp',
}

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { error } = await requireAuth()
  if (error) return error

  // Find the file by ID prefix
  const files = fs.readdirSync(UPLOADS_PATH)
  const match = files.find(f => f.startsWith(params.id + '.'))
  if (!match) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const filePath = path.join(UPLOADS_PATH, match)
  const ext = match.split('.').pop()?.toLowerCase() || ''
  const mime = MIME_MAP[ext] || 'application/octet-stream'

  const buffer = fs.readFileSync(filePath)
  return new NextResponse(buffer, {
    headers: {
      'Content-Type': mime,
      'Cache-Control': 'public, max-age=31536000, immutable',
    },
  })
}
