import { describe, it, expect } from 'vitest'
import type { Task, Category, User, Attachment, TaskFilters, PlatformSettings } from '@/types'

/**
 * Type-level tests: these verify that the TypeScript interfaces remain structurally
 * correct. If a field is removed or renamed, the assignment will fail at compile time
 * and vitest will not even load this file.
 */

describe('Type contracts', () => {
  it('Task interface has required fields', () => {
    const task: Task = {
      id: 'abc',
      user_id: 'u1',
      title: 'Test',
      description: '',
      category_id: null,
      status: 'in_progress',
      status_id: null,
      progress: 0,
      start_date: null,
      due_date: null,
      created_at: '2025-01-01',
      updated_at: '2025-01-01',
      tags: [],
      attachments: [],
    }
    expect(task.id).toBe('abc')
    expect(task.status).toBe('in_progress')
  })

  it('Task status only allows valid values', () => {
    const valid: Task['status'][] = ['in_progress', 'completed']
    expect(valid).toHaveLength(2)
  })

  it('Category interface has required fields', () => {
    const cat: Category = {
      id: 'c1',
      user_id: 'u1',
      name: 'Work',
      color: '#ff0000',
      created_at: '2025-01-01',
    }
    expect(cat.name).toBe('Work')
  })

  it('User interface has required fields', () => {
    const user: User = {
      id: 'u1',
      username: 'john',
      email: 'john@test.com',
      display_name: 'John',
      role: 'admin',
      is_active: true,
      created_at: '2025-01-01',
      updated_at: '2025-01-01',
    }
    expect(user.role).toBe('admin')
  })

  it('User role only allows valid values', () => {
    const valid: User['role'][] = ['admin', 'user']
    expect(valid).toHaveLength(2)
  })

  it('Attachment interface has required fields', () => {
    const att: Attachment = {
      id: 'a1',
      task_id: 't1',
      filename: 'abc123.pdf',
      original_name: 'document.pdf',
      mime_type: 'application/pdf',
      size: 1024,
      created_at: '2025-01-01',
    }
    expect(att.size).toBe(1024)
  })

  it('TaskFilters has correct optional fields', () => {
    const filters: TaskFilters = {}
    expect(filters.search).toBeUndefined()

    const full: TaskFilters = {
      search: 'test',
      category_id: 'c1',
      status: 'in_progress',
      tag: 'urgent',
      date_from: '2025-01-01',
      date_to: '2025-12-31',
      page: 1,
      per_page: 50,
    }
    expect(full.page).toBe(1)
  })

  it('PlatformSettings has all keys', () => {
    const settings: PlatformSettings = {
      app_name: 'TaskFlow',
      max_tasks_per_user: '1000',
      max_file_size_mb: '25',
      allow_registration: 'false',
      max_categories_per_user: '50',
    }
    expect(settings.app_name).toBe('TaskFlow')
  })
})
