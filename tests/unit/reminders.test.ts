import { describe, expect, it } from 'vitest'
import { resolveReminderNotificationStatus } from '@/lib/reminders'

describe('resolveReminderNotificationStatus', () => {
  it('returns failed when response is not ok', () => {
    expect(resolveReminderNotificationStatus({ responseOk: false })).toBe('failed')
  })

  it('prioritizes failed status over other meta when response is not ok', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: false,
      notificationAvailable: false,
      notificationDispatched: true,
    })).toBe('failed')
  })

  it('prioritizes failed status over a dispatched reason when response is not ok', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: false,
      notificationAvailable: true,
      notificationReason: 'dispatched',
    })).toBe('failed')
  })

  it('returns unavailable when webhook is unavailable', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: false,
    })).toBe('unavailable')
  })

  it('returns nothing_due when reminders endpoint reports no pending reminders', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: true,
      notificationDispatched: false,
      notificationReason: 'no_pending_reminders',
    })).toBe('nothing_due')
  })

  it('returns nothing_due when no_pending_reminders conflicts with unavailable metadata', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: false,
      notificationDispatched: false,
      notificationReason: 'no_pending_reminders',
    })).toBe('nothing_due')
  })

  it('returns unavailable when reason reports missing webhook configuration', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: true,
      notificationReason: 'no_webhook_configured',
    })).toBe('unavailable')
  })

  it('returns unavailable when no_webhook_configured reason conflicts with dispatched=true', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: false,
      notificationReason: 'no_webhook_configured',
      notificationDispatched: true,
    })).toBe('unavailable')
  })

  it('returns failed when reason reports webhook dispatch failure', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: true,
      notificationReason: 'webhook_failed',
      notificationDispatched: false,
    })).toBe('failed')
  })

  it('returns sent when reason reports dispatched', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: true,
      notificationReason: 'dispatched',
    })).toBe('sent')
  })

  it('returns sent when reason is not_requested but response is ok', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: true,
      notificationReason: 'not_requested',
    })).toBe('sent')
  })

  it('returns failed when not_requested is paired with dispatch=false', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: true,
      notificationReason: 'not_requested',
      notificationDispatched: false,
    })).toBe('failed')
  })

  it('returns failed when dispatch result is false', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: true,
      notificationDispatched: false,
    })).toBe('failed')
  })

  it('returns sent when request is ok and dispatch is not reported as false', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: true,
      notificationDispatched: true,
    })).toBe('sent')

    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: true,
    })).toBe('sent')
  })

  it('treats unavailable as higher priority than dispatched=true', () => {
    expect(resolveReminderNotificationStatus({
      responseOk: true,
      notificationAvailable: false,
      notificationDispatched: true,
    })).toBe('unavailable')
  })
})
