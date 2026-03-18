import { describe, it, expect, beforeEach } from 'vitest'
import type Database from 'better-sqlite3'
import { createTestDb } from '../helpers/test-db'

let db: Database.Database

beforeEach(() => {
  db = createTestDb()
})

describe('Platform settings', () => {
  const defaults: Record<string, string> = {
    app_name: 'TaskFlow',
    max_tasks_per_user: '1000',
    max_file_size_mb: '25',
    allow_registration: 'false',
    max_categories_per_user: '50',
    require_admin_approval: 'false',
  }

  it('inserts default settings', () => {
    const insert = db.prepare('INSERT OR IGNORE INTO platform_settings (key, value) VALUES (?, ?)')
    for (const [key, value] of Object.entries(defaults)) {
      insert.run(key, value)
    }

    const settings = db.prepare('SELECT * FROM platform_settings').all() as { key: string; value: string }[]
    expect(settings).toHaveLength(Object.keys(defaults).length)
  })

  it('updates a setting', () => {
    db.prepare("INSERT INTO platform_settings (key, value) VALUES ('app_name', 'TaskFlow')").run()
    db.prepare("UPDATE platform_settings SET value = ? WHERE key = ?").run('MyApp', 'app_name')

    const row = db.prepare("SELECT value FROM platform_settings WHERE key = 'app_name'").get() as { value: string }
    expect(row.value).toBe('MyApp')
  })

  it('INSERT OR IGNORE does not overwrite existing', () => {
    db.prepare("INSERT INTO platform_settings (key, value) VALUES ('app_name', 'Custom')").run()
    db.prepare("INSERT OR IGNORE INTO platform_settings (key, value) VALUES ('app_name', 'Default')").run()

    const row = db.prepare("SELECT value FROM platform_settings WHERE key = 'app_name'").get() as { value: string }
    expect(row.value).toBe('Custom')
  })
})
