export type ReminderNotificationStatus = 'idle' | 'sent' | 'failed' | 'unavailable' | 'nothing_due'

export type ReminderNotificationReason =
  | 'not_requested'
  | 'dispatched'
  | 'no_webhook_configured'
  | 'no_pending_reminders'
  | 'webhook_failed'

export type ReminderMeta = {
  notification_attempted?: boolean
  notification_dispatched?: boolean
  notification_available?: boolean
  notification_reason?: ReminderNotificationReason
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
  notificationReason?: ReminderNotificationReason
}): Exclude<ReminderNotificationStatus, 'idle'> {
  if (!input.responseOk) return 'failed'
  if (input.notificationReason === 'no_pending_reminders') return 'nothing_due'
  if (input.notificationAvailable === false) return 'unavailable'
  if (input.notificationDispatched === false) return 'failed'
  return 'sent'
}
