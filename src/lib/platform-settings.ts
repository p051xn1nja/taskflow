import type Database from 'better-sqlite3'
import { getDb } from './db'

type SettingRow = { value: string } | undefined

export interface PlatformSettings {
  maxTasksPerUser: number
  maxCategoriesPerUser: number
  maxFileSizeMb: number
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(value || '', 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

function getSetting(db: Database.Database, key: string): SettingRow {
  return db.prepare('SELECT value FROM platform_settings WHERE key = ?').get(key) as SettingRow
}

export function getPlatformSettings(db: Database.Database = getDb()): PlatformSettings {
  const maxTasksPerUser = parsePositiveInt(getSetting(db, 'max_tasks_per_user')?.value, 1000)
  const maxCategoriesPerUser = parsePositiveInt(getSetting(db, 'max_categories_per_user')?.value, 50)
  const maxFileSizeMb = parsePositiveInt(getSetting(db, 'max_file_size_mb')?.value, 25)

  return { maxTasksPerUser, maxCategoriesPerUser, maxFileSizeMb }
}

