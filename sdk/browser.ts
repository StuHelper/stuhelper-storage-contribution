// Authenticated transport is supplied by the host application. This SDK never
// fabricates identities, stores tokens, or makes client-side access decisions.
import type { components } from './contribution.gen';

export type Contribution = components['schemas']['Contribution'];
export type Policy = components['schemas']['Policy'];
export type Statistics = components['schemas']['Statistics'];
export type Page = components['schemas']['Page'];
export type Candidates = components['schemas']['Candidates'];
export type Conditions = components['schemas']['Conditions'];
export type Command = components['schemas']['CommandRequest'];
export type Create = components['schemas']['CreateRequest'];
export type Operation =
  | { kind: 'create'; key: string; body: Create }
  | { kind: 'command'; key: string; id: string; body: Command }
  | { kind: 'retry'; key: string; id: string; body: components['schemas']['RetryRequest'] };

type ErrorCode = 'conflict' | 'forbidden' | 'incompatible' | 'invalid' | 'network' | 'unauthenticated' | 'unavailable';
export class ContributionError extends Error {
  constructor(public readonly code: ErrorCode, public readonly uncertain = false) { super(code); }
}
function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new ContributionError('incompatible');
  return value as Record<string, unknown>; // Object shape established; each consumed field is validated below.
}
function text(value: unknown, max = 512): string {
  if (typeof value !== 'string' || value.length > max) throw new ContributionError('incompatible');
  return value;
}
function integer(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new ContributionError('incompatible');
  return value;
}
function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new ContributionError('incompatible');
  return value;
}
function date(value: unknown): string {
  const result = text(value);
  if (!/(?:Z|[+-]\d\d:\d\d)$/.test(result) || !Number.isFinite(Date.parse(result))) throw new ContributionError('incompatible');
  return result;
}
function oneOf<T extends string>(value: unknown, choices: readonly T[]): T {
  for (const choice of choices) if (value === choice) return choice;
  throw new ContributionError('incompatible');
}
function list<T>(value: unknown, parse: (v: unknown) => T): T[] {
  if (!Array.isArray(value) || value.length > 100) throw new ContributionError('incompatible');
  return value.map((item: unknown) => parse(item));
}
function terms(value: unknown): Policy['terms'] {
  const v = object(value); const url = text(v.url);
  try { const u = new URL(url); if (u.protocol !== 'https:' || u.username || u.password) throw new Error(); }
  catch { throw new ContributionError('incompatible'); }
  const digest = text(v.digest); if (!/^[a-f0-9]{64}$/.test(digest)) throw new ContributionError('incompatible');
  return { version: text(v.version), digest, url };
}
export function parsePolicy(value: unknown): Policy {
  const v = object(value);
  const result = { terms: terms(v.terms), adapters: list(v.adapters, value => text(value, 128)), min_bytes: integer(v.min_bytes), max_bytes: integer(v.max_bytes), min_term_seconds: integer(v.min_term_seconds), max_term_seconds: integer(v.max_term_seconds), exit_target_seconds: integer(v.exit_target_seconds), max_per_owner: integer(v.max_per_owner), observation_max_age_seconds: integer(v.observation_max_age_seconds) };
  if (result.min_bytes < 1 || result.max_bytes < result.min_bytes || result.min_term_seconds < 1 || result.max_term_seconds < result.min_term_seconds) throw new ContributionError('incompatible');
  return result;
}
export function parseContribution(value: unknown): Contribution {
  const v = object(value); const c = object(v.conditions);
  const result: Contribution = {
    id: text(v.id, 128), adapter: text(v.adapter, 128), revision: integer(v.revision), applied_revision: integer(v.applied_revision),
    desired_state: oneOf(v.desired_state, ['active', 'paused', 'exiting', 'revoked']),
    state: oneOf(v.state, ['pending', 'active', 'paused', 'exiting', 'blocked', 'exited', 'revoked']), reason: text(v.reason),
    conditions: { limit_bytes: integer(c.limit_bytes), personal_reserve: integer(c.personal_reserve), until: date(c.until) },
    consent: terms(v.consent), accepted_at: date(v.accepted_at), created_at: date(v.created_at), updated_at: date(v.updated_at),
  };
  if (result.revision < 1 || result.applied_revision > result.revision) throw new ContributionError('incompatible');
  if (v.exit_requested_at !== undefined) result.exit_requested_at = date(v.exit_requested_at);
  if (v.exit_target_at !== undefined) result.exit_target_at = date(v.exit_target_at);
  if (v.observation !== undefined) {
    const o = object(v.observation);
    result.observation = { observed_at: date(o.observed_at), authorization_expires_at: date(o.authorization_expires_at), quota_expires_at: date(o.quota_expires_at), authorized: boolean(o.authorized), used_bytes: integer(o.used_bytes), reserved_bytes: integer(o.reserved_bytes), available_bytes: integer(o.available_bytes), remaining_replicas: integer(o.remaining_replicas) };
  }
  return result;
}
export function parsePage(value: unknown): Page {
  const v = object(value); return { items: list(v.items, parseContribution), next_cursor: text(v.next_cursor, 128) };
}
export function parseCandidates(value: unknown): Candidates {
  const v = object(value); return { items: list(v.items, value => { const i = object(value); return { id: text(i.id, 128), adapter: text(i.adapter, 128), available_bytes: integer(i.available_bytes), authorization_expires_at: date(i.authorization_expires_at) }; }), next_cursor: text(v.next_cursor, 128) };
}
export function parseStatistics(value: unknown): Statistics {
  const v = object(value);
  return { declared_bytes: integer(v.declared_bytes), available_bytes: integer(v.available_bytes), used_bytes: integer(v.used_bytes), reserved_bytes: integer(v.reserved_bytes), contributions: integer(v.contributions), fresh_observations: integer(v.fresh_observations), status: oneOf(v.status, ['current', 'partial']), generated_at: date(v.generated_at) };
}

export function contributionAPI(fetcher: typeof fetch = fetch) {
  const base = '/api/v1/storage-contributions';
  async function request(path: string, signal: AbortSignal, operation?: Operation): Promise<unknown> {
    let response: Response;
    try {
      response = await fetcher(base + path, { method: operation ? 'POST' : 'GET', signal, credentials: 'same-origin', cache: 'no-store', headers: operation ? { Accept: 'application/json', 'Content-Type': 'application/json', 'Idempotency-Key': operation.key } : { Accept: 'application/json' }, body: operation ? JSON.stringify(operation.body) : undefined });
    } catch { throw new ContributionError('network', !!operation); }
    if (!response.ok) {
      if (response.status === 401) throw new ContributionError('unauthenticated');
      if (response.status === 403) throw new ContributionError('forbidden');
      if (response.status === 400) throw new ContributionError('invalid');
      if (response.status === 404 || response.status === 409) throw new ContributionError('conflict');
      throw new ContributionError('unavailable', !!operation);
    }
    if (operation && response.status !== 202) throw new ContributionError('incompatible', true);
    try { return await response.json(); } catch { throw new ContributionError('incompatible', !!operation); }
  }
  const query = (after: string) => '?' + new URLSearchParams({ limit: '25', after });
  return {
    async policy(signal: AbortSignal) { return parsePolicy(await request('/policy', signal)); },
    async statistics(signal: AbortSignal) { return parseStatistics(await request('/statistics', signal)); },
    async options(signal: AbortSignal, after = '') { return parseCandidates(await request('/options' + query(after), signal)); },
    async list(signal: AbortSignal, after = '', admin = false) { return parsePage(await request((admin ? '/operations' : '') + query(after), signal)); },
    async get(signal: AbortSignal, id: string) { return parseContribution(await request('/' + encodeURIComponent(id), signal)); },
    async execute(operation: Operation, signal: AbortSignal) {
      const path = operation.kind === 'create' ? '' : operation.kind === 'retry' ? '/operations/' + encodeURIComponent(operation.id) + '/retry' : '/' + encodeURIComponent(operation.id) + '/commands';
      const result = await request(path, signal, operation);
      try { const v = parseContribution(result); if (operation.kind !== 'create' && v.id !== operation.id) throw new Error(); return v; }
      catch { throw new ContributionError('incompatible', true); }
    },
  };
}
