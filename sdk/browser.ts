// Authenticated transport is supplied by the host application. This SDK never
// fabricates identities, stores tokens, or makes client-side access decisions.
import type { components } from './contribution.gen';

export type Contribution = components['schemas']['Contribution'];
export type OwnerContribution = components['schemas']['OwnerContribution'];
export type OwnerPage = components['schemas']['OwnerPage'];
export type ProviderCapacity = components['schemas']['ProviderCapacity'];
export type Policy = components['schemas']['Policy'];
export type Statistics = components['schemas']['Statistics'];
export type MetricsSnapshot = components['schemas']['MetricsSnapshot'];
export type Page = components['schemas']['Page'];
export type Candidates = components['schemas']['Candidates'];
export type Conditions = components['schemas']['Conditions'];
export type Command = components['schemas']['CommandRequest'];
export type Create = components['schemas']['CreateRequest'];
export interface OperationsFilter {
  state?: Contribution['state'];
  reason?: string;
  adapter?: string;
}
export type Operation =
  | { kind: 'create'; key: string; body: Create }
  | { kind: 'command'; key: string; id: string; body: Command }
  | { kind: 'retry'; key: string; id: string; body: components['schemas']['RetryRequest'] };

export type ErrorDetailCode = NonNullable<components['schemas']['Error']['detail_code']>;

const DETAIL_CODES: readonly ErrorDetailCode[] = [
  'revision_conflict',
  'idempotency_mismatch',
  'owner_quota_exceeded',
  'registry_full',
  'already_bound',
  'instance_not_eligible',
  'limit_below_occupied',
  'invalid_state_transition',
  'terms_version_mismatch',
  'limit_out_of_range',
  'term_out_of_range',
  'limit_exceeds_provider_capacity',
  'provider_capacity_unavailable',
];

const IDENTIFIER = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/;
const RESERVED_PATHS = new Set(['policy', 'statistics', 'options', 'operations']);

type ErrorCode = 'conflict' | 'forbidden' | 'incompatible' | 'invalid' | 'network' | 'not_found' | 'unauthenticated' | 'unavailable';
export class ContributionError extends Error {
  readonly code: ErrorCode;
  readonly uncertain: boolean;
  readonly detailCode?: ErrorDetailCode;
  readonly minRequiredBytes?: number;
  constructor(code: ErrorCode, uncertain = false, detailCode?: ErrorDetailCode, minRequiredBytes?: number) {
    super(code);
    this.code = code;
    this.uncertain = uncertain;
    this.detailCode = detailCode;
    this.minRequiredBytes = minRequiredBytes;
  }
}
async function errorDetails(response: Response): Promise<{ detailCode?: ErrorDetailCode; minRequiredBytes?: number }> {
  try {
    const v = object(await response.json());
    const detailCode = v.detail_code !== undefined ? oneOf(v.detail_code, DETAIL_CODES) : undefined;
    const minRequiredBytes = v.min_required_bytes !== undefined ? integer(v.min_required_bytes) : undefined;
    if (minRequiredBytes !== undefined && minRequiredBytes > 70368744177664) return { detailCode };
    return { detailCode, minRequiredBytes };
  } catch {
    return {};
  }
}
function validId(value: string, allowReserved = false): string {
  if (!IDENTIFIER.test(value) || (!allowReserved && RESERVED_PATHS.has(value))) throw new ContributionError('invalid', false);
  return encodeURIComponent(value);
}
function validCursor(after: string): string {
  if (after !== '' && !IDENTIFIER.test(after)) throw new ContributionError('invalid', false);
  return after;
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
  const result = { terms: terms(v.terms), adapters: list(v.adapters, value => text(value, 128)), min_bytes: integer(v.min_bytes), max_bytes: integer(v.max_bytes), min_term_seconds: integer(v.min_term_seconds), max_term_seconds: integer(v.max_term_seconds), exit_target_seconds: integer(v.exit_target_seconds), max_per_owner: integer(v.max_per_owner), observation_max_age_seconds: integer(v.observation_max_age_seconds), renewal_notice_seconds: integer(v.renewal_notice_seconds) };
  if (result.min_bytes < 1 || result.max_bytes < result.min_bytes || result.min_term_seconds < 1 || result.max_term_seconds < result.min_term_seconds || result.renewal_notice_seconds < 1) throw new ContributionError('incompatible');
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
  if (result.conditions.limit_bytes < 1 || result.revision < 1 || result.applied_revision > result.revision) throw new ContributionError('incompatible');
  if (v.warnings !== undefined) result.warnings = list(v.warnings, item => oneOf(item, ['consent_expiring_soon', 'authorization_expiring_soon']));
  if (v.exit_requested_at !== undefined) result.exit_requested_at = date(v.exit_requested_at);
  if (v.exit_target_at !== undefined) result.exit_target_at = date(v.exit_target_at);
  if (v.account_hint !== undefined) result.account_hint = text(v.account_hint, 256);
  if (v.display_label !== undefined) {
    const label = text(v.display_label, 128);
    if ([...label].length > 32) throw new ContributionError('incompatible');
    result.display_label = label;
  }
  if (v.exit_initial_replicas !== undefined) result.exit_initial_replicas = integer(v.exit_initial_replicas);
  if (v.exit_initial_used_bytes !== undefined) result.exit_initial_used_bytes = integer(v.exit_initial_used_bytes);
  if (v.observation !== undefined) {
    const o = object(v.observation);
    result.observation = { observed_at: o.observed_at === null ? null : date(o.observed_at), authorization_expires_at: date(o.authorization_expires_at), quota_expires_at: date(o.quota_expires_at), authorized: boolean(o.authorized), used_bytes: integer(o.used_bytes), reserved_bytes: integer(o.reserved_bytes), available_bytes: integer(o.available_bytes), remaining_replicas: integer(o.remaining_replicas) };
  }
  if (v.verified_active_seconds !== undefined) result.verified_active_seconds = integer(v.verified_active_seconds);
  if (v.verified_available_byte_hours !== undefined) result.verified_available_byte_hours = integer(v.verified_available_byte_hours);
  if (v.verified_used_byte_hours !== undefined) result.verified_used_byte_hours = integer(v.verified_used_byte_hours);
  if (v.job_state !== undefined) result.job_state = oneOf(v.job_state, ['pending', 'running', 'blocked', 'complete'] as const);
  if (v.attempts !== undefined) result.attempts = integer(v.attempts);
  if (v.max_attempts !== undefined) {
    const maxAttempts = integer(v.max_attempts);
    if (maxAttempts < 1) throw new ContributionError('incompatible');
    result.max_attempts = maxAttempts;
  }
  if (v.available_at !== undefined) result.available_at = date(v.available_at);
  return result;
}
function countMap(value: unknown): Record<string, number> {
  const v = object(value);
  const entries = Object.entries(v);
  if (entries.length > 100) throw new ContributionError('incompatible');
  const out: Record<string, number> = {};
  for (const [k, raw] of entries) out[text(k, 128)] = integer(raw);
  return out;
}
export function parseMetricsSnapshot(value: unknown): MetricsSnapshot {
  const v = object(value);
  return {
    by_state: countMap(v.by_state),
    by_reason: countMap(v.by_reason),
    by_job_state: countMap(v.by_job_state),
    exit_overdue: integer(v.exit_overdue),
    cleanup_unconfirmed: integer(v.cleanup_unconfirmed),
    pending_outbox: integer(v.pending_outbox),
    generated_at: date(v.generated_at),
  };
}
export function parsePage(value: unknown): Page {
  const v = object(value); return { items: list(v.items, parseContribution), next_cursor: text(v.next_cursor, 128) };
}

function parseProviderCapacity(value: unknown): ProviderCapacity {
  // Responses created before the quota API lack the provider_capacity field.
  if (value === undefined) {
    return { total_bytes: null, used_bytes: null, remaining_bytes: null, observed_at: null, status: 'not_read' };
  }
  const v = object(value);
  const status = oneOf(v.status, ['available', 'not_read', 'read_failed', 'expired'] as const);
  const observedAt = v.observed_at === null ? null : date(v.observed_at);
  if (status === 'available') {
    if (observedAt === null) throw new ContributionError('incompatible');
    return {
      total_bytes: integer(v.total_bytes),
      used_bytes: integer(v.used_bytes),
      remaining_bytes: integer(v.remaining_bytes),
      observed_at: observedAt,
      status,
    };
  }
  if (v.total_bytes !== null || v.used_bytes !== null || v.remaining_bytes !== null) {
    throw new ContributionError('incompatible');
  }
  const recovery = v.recovery === undefined ? undefined : oneOf(v.recovery, ['waiting_retry', 'waiting_scan', 'credentials_required'] as const);
  if (recovery !== undefined && status !== 'read_failed') throw new ContributionError('incompatible');
  return { total_bytes: null, used_bytes: null, remaining_bytes: null, observed_at: observedAt, status, ...(recovery ? { recovery } : {}) };
}

export function parseOwnerContribution(value: unknown): OwnerContribution {
  return { ...parseContribution(value), provider_capacity: parseProviderCapacity(object(value).provider_capacity) };
}

export function parseOwnerPage(value: unknown): OwnerPage {
  const v = object(value);
  return { items: list(v.items, parseOwnerContribution), next_cursor: text(v.next_cursor, 128) };
}

function parseCandidate(value: unknown): Candidates['items'][number] {
  const v = object(value);
  const capacity = parseProviderCapacity(v.provider_capacity);
  const legacy = v.provider_capacity === undefined && v.safety_margin_bytes === undefined && v.max_contributable_bytes === undefined;
  const safetyMargin = legacy ? 0 : integer(v.safety_margin_bytes);
  const maxContributable = legacy || v.max_contributable_bytes === null ? null : integer(v.max_contributable_bytes);
  const expectedLimit = capacity.remaining_bytes === null ? null : Math.max(0, capacity.remaining_bytes - safetyMargin);
  if (maxContributable !== expectedLimit) throw new ContributionError('incompatible');
  return {
    id: text(v.id, 128),
    adapter: text(v.adapter, 128),
    ...(v.account_hint === undefined ? {} : { account_hint: text(v.account_hint, 256) }),
    available_bytes: integer(v.available_bytes),
    authorization_expires_at: date(v.authorization_expires_at),
    ...(v.quota_expires_at === undefined ? {} : { quota_expires_at: date(v.quota_expires_at) }),
    ...(v.reason === undefined ? {} : { reason: text(v.reason) }),
    provider_capacity: capacity,
    safety_margin_bytes: safetyMargin,
    max_contributable_bytes: maxContributable,
  };
}
export function parseCandidates(value: unknown): Candidates {
  const v = object(value);
  return { items: list(v.items, parseCandidate), next_cursor: text(v.next_cursor, 128) };
}
export function parseStatistics(value: unknown): Statistics {
  const v = object(value);
  return { declared_bytes: integer(v.declared_bytes), available_bytes: integer(v.available_bytes), used_bytes: integer(v.used_bytes), reserved_bytes: integer(v.reserved_bytes), contributions: integer(v.contributions), fresh_observations: integer(v.fresh_observations), status: oneOf(v.status, ['current', 'partial']), generated_at: date(v.generated_at) };
}

export function contributionAPI(fetcher: typeof fetch = fetch) {
  const base = '/api/v1/storage-contributions';
  async function request(path: string, signal: AbortSignal, operation?: Operation): Promise<unknown> {
    signal.throwIfAborted();
    if (operation && !/^[ -~]{1,128}$/.test(operation.key)) throw new ContributionError('invalid');
    let response: Response;
    try {
      response = await fetcher(base + path, { method: operation ? 'POST' : 'GET', signal, credentials: 'same-origin', cache: 'no-store', headers: operation ? { Accept: 'application/json', 'Content-Type': 'application/json', 'Idempotency-Key': operation.key } : { Accept: 'application/json' }, body: operation ? JSON.stringify(operation.body) : undefined });
    } catch { signal.throwIfAborted(); throw new ContributionError('network', !!operation); }
    if (!response.ok) {
      if (response.status === 401) throw new ContributionError('unauthenticated');
      if (response.status === 403) throw new ContributionError('forbidden');
      if (response.status === 400) {
        const { detailCode, minRequiredBytes } = await errorDetails(response);
        signal.throwIfAborted();
        throw new ContributionError('invalid', false, detailCode, minRequiredBytes);
      }
      if (response.status === 404 || response.status === 409) {
        const { detailCode, minRequiredBytes } = await errorDetails(response);
        signal.throwIfAborted();
        throw new ContributionError(response.status === 404 ? 'not_found' : 'conflict', false, detailCode, minRequiredBytes);
      }
      throw new ContributionError('unavailable', !!operation);
    }
    if (operation && response.status !== 202) throw new ContributionError('incompatible', true);
    try { return await response.json(); } catch { signal.throwIfAborted(); throw new ContributionError('incompatible', !!operation); }
  }
  const query = (after: string, filter?: OperationsFilter) => {
    const params = new URLSearchParams({ limit: '25', after:validCursor(after) });
    if (filter?.state) params.set('state', filter.state);
    if (filter?.reason) params.set('reason', filter.reason);
    if (filter?.adapter) params.set('adapter', filter.adapter);
    return '?' + params;
  };
  function listContributions(signal: AbortSignal, after?: string, admin?: false): Promise<OwnerPage>;
  function listContributions(signal: AbortSignal, after: string | undefined, admin: true, filter?: OperationsFilter): Promise<Page>;
  function listContributions(signal: AbortSignal, after: string | undefined, admin: boolean | undefined, filter?: OperationsFilter): Promise<Page | OwnerPage>;
  async function listContributions(signal: AbortSignal, after = '', admin = false, filter?: OperationsFilter) {
    if (admin) return parsePage(await request('/operations' + query(after, filter), signal));
    return parseOwnerPage(await request(query(after), signal));
  }
  return {
    async policy(signal: AbortSignal) { return parsePolicy(await request('/policy', signal)); },
    async statistics(signal: AbortSignal) { return parseStatistics(await request('/statistics', signal)); },
    async metrics(signal: AbortSignal) { return parseMetricsSnapshot(await request('/operations/metrics', signal)); },
    async options(signal: AbortSignal, after = '') { return parseCandidates(await request('/options' + query(after), signal)); },
    list: listContributions,
    async get(signal: AbortSignal, id: string) { return parseOwnerContribution(await request('/' + validId(id), signal)); },
    async execute(operation: Operation, signal: AbortSignal) {
      const path = operation.kind === 'create' ? '' : operation.kind === 'retry' ? '/operations/' + validId(operation.id, true) + '/retry' : '/' + validId(operation.id) + '/commands';
      const result = await request(path, signal, operation);
      try { const v = parseContribution(result); if (operation.kind !== 'create' && v.id !== operation.id) throw new Error(); return v; }
      catch { throw new ContributionError('incompatible', true); }
    },
  };
}
