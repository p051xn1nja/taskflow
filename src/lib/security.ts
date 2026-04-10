import { createHash } from 'crypto'

type RateLimitBucket = {
  count: number
  resetAt: number
}

const buckets = new Map<string, RateLimitBucket>()

export function checkRateLimit(key: string, options?: { limit?: number; windowMs?: number }) {
  const limit = options?.limit ?? 10
  const windowMs = options?.windowMs ?? 60_000
  const now = Date.now()
  const bucket = buckets.get(key)

  if (!bucket || bucket.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs })
    return { allowed: true, remaining: limit - 1, resetAt: now + windowMs }
  }

  if (bucket.count >= limit) {
    return { allowed: false, remaining: 0, resetAt: bucket.resetAt }
  }

  bucket.count += 1
  return { allowed: true, remaining: limit - bucket.count, resetAt: bucket.resetAt }
}

export function getClientIdentifier(req: Request) {
  const forwarded = req.headers.get('x-forwarded-for') || ''
  const ip = forwarded.split(',')[0]?.trim() || req.headers.get('x-real-ip') || 'unknown'
  return createHash('sha256').update(ip).digest('hex').slice(0, 16)
}

export function sanitizeRichHtml(input: string) {
  // Basic allowlist-style cleanup (defense in depth against script/event-handler payloads)
  // This is intentionally conservative and strips common executable vectors.
  return input
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, '')
    .replace(/\son[a-z]+\s*=\s*(['"]).*?\1/gi, '')
    .replace(/\son[a-z]+\s*=\s*[^\s>]+/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/data:text\/html/gi, '')
}

export function isSafeProfileFilename(filename: string) {
  return /^profile_[a-f0-9]{24}\.(png|jpe?g|gif|webp)$/i.test(filename)
}
