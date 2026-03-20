import { NextResponse } from 'next/server'
import { getDb } from '@/lib/db'

export async function GET() {
  const db = getDb()
  const row = db.prepare("SELECT value FROM platform_settings WHERE key = 'app_name'").get() as { value: string } | undefined
  return NextResponse.json({ app_name: row?.value || 'TaskFlow' })
}
