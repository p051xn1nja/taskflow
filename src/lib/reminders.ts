export type ReminderNotificationStatus = 'idle' | 'sent' | 'failed' | 'unavailable'

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
