import { NextResponse } from 'next/server'
import { getDb, UPLOADS_PATH } from '@/lib/db'
import { requireAuth } from '@/lib/api-helpers'
import fs from 'fs'
import path from 'path'

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const attachment = db.prepare(`
    SELECT a.* FROM attachments a
    JOIN tasks t ON a.task_id = t.id
    WHERE a.id = ? AND t.user_id = ?
  `).get(params.id, session!.user.id) as { filename: string; original_name: string; mime_type: string } | undefined

  if (!attachment) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const filePath = path.join(UPLOADS_PATH, attachment.filename)
  if (!fs.existsSync(filePath)) return NextResponse.json({ error: 'File missing' }, { status: 404 })

  const buffer = fs.readFileSync(filePath)
  return new NextResponse(buffer, {
    headers: {
      'Content-Type': attachment.mime_type,
      'Content-Disposition': `attachment; filename="${encodeURIComponent(attachment.original_name)}"`,
    },
  })
}

export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const { error, session } = await requireAuth()
  if (error) return error

  const db = getDb()
  const attachment = db.prepare(`
    SELECT a.* FROM attachments a
    JOIN tasks t ON a.task_id = t.id
    WHERE a.id = ? AND t.user_id = ?
  `).get(params.id, session!.user.id) as { filename: string } | undefined

  if (!attachment) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const filePath = path.join(UPLOADS_PATH, attachment.filename)
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath)

  db.prepare('DELETE FROM attachments WHERE id = ?').run(params.id)
  return NextResponse.json({ success: true })
}
