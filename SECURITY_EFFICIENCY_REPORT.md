# Security & Efficiency Audit Report

Date: 2026-04-10  
Repository: `taskflow`

## Scope & Method

I performed a static code review across API routes, auth/session handling, DB schema/query patterns, and key frontend rendering points. No dynamic penetration testing was performed.

---

## Executive Summary

The codebase is generally structured and uses parameterized SQL queries consistently, which helps reduce SQL injection risk. However, there are several high-impact security weaknesses and multiple performance/code-quality issues:

- **High-risk security findings**:
  1. **Path traversal / local file read** in profile photo serving route.
  2. **Weak production secret fallback** for NextAuth.
  3. **Cross-tenant status assignment risk** due missing ownership validation and DB FK coverage for `tasks.status_id`.
- **Medium-risk findings**:
  - Stored HTML rendered with `dangerouslySetInnerHTML` without explicit sanitization control at API boundaries.
  - No evident authentication rate-limiting for credential endpoints.
- **Efficiency concerns**:
  - Blocking sync file I/O in request handlers.
  - Full upload directory scans per editor-image fetch.
  - Date function wrapping (`date(column)`) inhibits index use.
  - Repeated per-record enrichment queries and duplicated tag logic.

---

## Security Findings

## 1) Path traversal in public profile-photo endpoint (High)

**Location**: `src/app/api/profile-photo/[id]/route.ts`.

The endpoint directly joins a URL parameter into a filesystem path:

- `const filename = params.id`
- `const filePath = path.join(UPLOADS_PATH, filename)`
- `fs.existsSync(filePath)` then `fs.readFileSync(filePath)`

Because `filename` is not normalized or constrained to a safe basename pattern, crafted values like `../taskflow.db` can escape the upload directory and read arbitrary local files if present and readable.

**Impact**: Arbitrary file disclosure (LFI/path traversal), including potential DB or secret leakage.

**Recommendation**:
- Reject filenames containing `/`, `\\`, or `..`.
- Require strict regex whitelist: e.g. `/^profile_[a-f0-9]{24}\.(png|jpe?g|gif|webp)$/`.
- Optionally resolve and verify the resulting path remains under `UPLOADS_PATH`.

---

## 2) Insecure NextAuth secret fallback in production path (High)

**Location**: `src/lib/auth.ts`.

`secret` falls back to a hardcoded development constant even in production:

- Logs warning, then returns `secret || 'dev-only-secret-not-for-production'`.

This can make JWT/session signing predictable when misconfigured deployments occur.

**Impact**: Session forgery risk if production starts without proper `NEXTAUTH_SECRET`.

**Recommendation**:
- In production (`NODE_ENV === 'production'`), throw an error at startup if `NEXTAUTH_SECRET` is missing.
- Keep fallback only for explicit development mode.

---

## 3) Cross-tenant status assignment / referential integrity gap (High)

**Locations**: `src/app/api/tasks/route.ts`, `src/app/api/tasks/[id]/route.ts`, `src/lib/db.ts`.

`status_id` provided by clients is not validated to ensure ownership (`statuses.user_id === session.user.id`) before write operations in task create/update. Additionally, the schema does not define a foreign key on `tasks.status_id`.

Result: a task can reference another user's status row (or stale/nonexistent status IDs in some migration paths), creating tenant integrity violations and unpredictable behavior.

**Impact**: Cross-tenant data integrity violation and potential information leakage via joined status metadata.

**Recommendation**:
- Validate `status_id` against `SELECT id FROM statuses WHERE id = ? AND user_id = ?` before insert/update.
- Add foreign key support for `tasks.status_id` (migration may require table rebuild in SQLite).
- Enforce status ownership at API layer and DB layer.

---

## 4) Stored HTML rendered without explicit sanitization contract (Medium)

**Locations**: note rendering UIs in `src/app/(app)/notes/page.tsx` and calendar view equivalent.

Note content is rendered via `dangerouslySetInnerHTML`. The API stores content directly from request payload (`content`) in notes routes without explicit sanitization guard in backend.

If editor constraints are bypassed (or malicious HTML is injected through API), persistent XSS is possible.

**Impact**: Stored XSS in authenticated context.

**Recommendation**:
- Sanitize HTML server-side on write (allowlist-based sanitizer).
- Optionally sanitize again before render as defense-in-depth.
- Consider CSP hardening.

---

## 5) Missing auth brute-force protections (Medium)

**Locations**: credential auth flow and setup route (`src/lib/auth.ts`, `src/app/api/auth/setup/route.ts`).

No explicit request throttling/lockout observed for login and registration endpoints.

**Impact**: Password spraying and brute-force risk, especially for internet-exposed deployments.

**Recommendation**:
- Add per-IP and per-account rate limiting.
- Add progressive backoff or temporary lockouts.
- Emit audit logs for repeated failed logins.

---

## Efficiency & Code Quality Findings

## 6) Synchronous file I/O in API handlers (Medium)

Several routes use blocking operations (`fs.writeFileSync`, `fs.readFileSync`, `fs.unlinkSync`, `fs.readdirSync`) inside request handlers.

**Impact**: Event-loop blocking under load; reduced throughput and tail latency spikes.

**Recommendation**:
- Use async `fs.promises` methods consistently.
- Batch independent deletes with `Promise.allSettled` where appropriate.

---

## 7) Editor upload fetch scans full upload directory each request (Medium)

**Location**: `src/app/api/editor-upload/[id]/route.ts`.

The route runs `readdirSync(UPLOADS_PATH)` then `find(...)` by prefix for each GET.

**Impact**: O(n) directory scan per request; scales poorly with attachment growth.

**Recommendation**:
- Store exact filename lookup in DB keyed by attachment ID.
- Or enforce deterministic extension mapping so direct path construction is possible.

---

## 8) Date-wrapped SQL predicates reduce index effectiveness (Medium)

**Location**: `src/app/api/calendar/route.ts` and other list endpoints.

Using `date(column)` in WHERE clauses (e.g., `date(t.created_at) >= ?`) often prevents efficient index usage in SQLite.

**Impact**: Slower range queries with larger datasets.

**Recommendation**:
- Store timestamps in ISO format (already done) and compare raw strings with normalized range boundaries.
- Add/adjust composite indexes for frequent filters (e.g., `(user_id, created_at)`, `(user_id, updated_at)`, `(user_id, status_id)`).

---

## 9) N+1 style enrichment patterns and repeated mapping logic (Low/Medium)

Multiple endpoints enrich entities with related rows through per-record queries or repeated ad-hoc logic.

**Impact**: Query overhead and maintainability drag.

**Recommendation**:
- Use batched joins/CTEs where practical.
- Consolidate shared tag/link enrichment routines into library helpers.

---

## 10) Validation consistency gaps (Low/Medium)

Dynamic update endpoints accept heterogeneous body shapes with limited schema validation.

Examples include broad body parsing with ad-hoc field checks; invalid values may surface as DB constraint errors rather than clean API responses.

**Impact**: Less predictable API behavior, weaker input contracts, and harder hardening.

**Recommendation**:
- Adopt a central schema validator (e.g., Zod) across all mutating routes.
- Enforce field length/type constraints and enum checks before DB writes.

---

## Notable Strengths

- Parameterized SQL usage is prevalent, reducing SQL injection risk.
- Role checks (`requireAdmin`) are centralized and easy to audit.
- Multi-tenant filtering by `user_id` is implemented in many critical queries.
- File upload endpoints apply size and extension controls.

---

## Priority Remediation Plan

1. **Immediate (P0)**
   - Fix profile-photo path traversal.
   - Remove production secret fallback.
   - Enforce status ownership checks and DB integrity for `tasks.status_id`.

2. **Near-term (P1)**
   - Add HTML sanitization contract for notes.
   - Add login/registration rate limiting.
   - Replace sync file APIs in request path.

3. **Medium-term (P2)**
   - Optimize calendar/date query predicates and indexing.
   - Remove directory scans in editor upload serving.
   - Refactor duplicated enrichment/validation logic.

