export type ReminderNotificationStatus = 'idle' | 'sent' | 'failed' | 'unavailable'

export type ReminderMeta = {
  notification_attempted?: boolean
  notification_dispatched?: boolean
  notification_available?: boolean
}

export type ReminderCounts = {
  overdue: number
  due_today: number
  next_7_days: number
}

export type ReminderResponse = {
  counts: ReminderCounts
  meta?: ReminderMeta
}

export function resolveReminderNotificationStatus(input: {
  responseOk: boolean
  notificationAvailable?: boolean
  notificationDispatched?: boolean
}): Exclude<ReminderNotificationStatus, 'idle'> {
  if (!input.responseOk) return 'failed'
  if (input.notificationAvailable === false) return 'unavailable'
  if (input.notificationDispatched === false) return 'failed'
  return 'sent'
}
