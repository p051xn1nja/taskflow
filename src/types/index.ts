export interface User {
  id: string
  username: string
  email: string
  display_name: string
  role: 'admin' | 'user'
  is_active: boolean
  profile_photo: string
  created_at: string
  updated_at: string
}

export interface Tag {
  id: string
  user_id: string
  name: string
  color: string
  created_at: string
  task_count?: number
  note_count?: number
}

export interface Status {
  id: string
  user_id: string
  name: string
  color: string
  position: number
  is_completed: boolean
  is_default: boolean
  created_at: string
  task_count?: number
}

export interface Task {
  id: string
  user_id: string
  title: string
  description: string
  category_id: string | null
  status: 'in_progress' | 'completed'
  status_id: string | null
  progress: number
  location: string
  start_date: string | null
  due_date: string | null
  recurrence: 'none' | 'daily' | 'weekly' | 'monthly'
  board_position: number
  created_at: string
  updated_at: string
  tags: Tag[]
  attachments: Attachment[]
  category?: Category | null
  task_status?: Status | null
}

export interface Category {
  id: string
  user_id: string
  name: string
  color: string
  created_at: string
  task_count?: number
  note_count?: number
}

export interface Attachment {
  id: string
  task_id: string
  filename: string
  original_name: string
  mime_type: string
  size: number
  created_at: string
}

export interface NoteAttachment {
  id: string
  note_id: string
  filename: string
  original_name: string
  mime_type: string
  size: number
  created_at: string
}

export interface Note {
  id: string
  user_id: string
  title: string
  content: string
  color: string
  category_id: string | null
  category_name?: string | null
  category_color?: string | null
  category?: Category | null
  created_at: string
  updated_at: string
  tags: Tag[]
  attachments: NoteAttachment[]
  linked_tasks: LinkedTask[]
}

export interface LinkedTask {
  id: string
  title: string
  status: 'in_progress' | 'completed'
  progress: number
}

export interface PlatformSettings {
  app_name: string
  max_tasks_per_user: string
  max_file_size_mb: string
  allow_registration: string
  max_categories_per_user: string
}

export interface TaskFilters {
  search?: string
  category_id?: string
  status?: string
  tag?: string
  date_from?: string
  date_to?: string
  page?: number
  per_page?: number
}

export interface NoteFilters {
  search?: string
  tag?: string
  page?: number
  per_page?: number
}
