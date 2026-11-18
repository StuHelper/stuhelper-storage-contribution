import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  contributionAPI,
  ContributionError,
  parseCandidates,
  parseContribution,
  parsePage,
  parsePolicy,
  parseStatistics,
  type Operation,
} from './browser.ts';

const validTerms = {
  version: 'terms-v1',
  digest: 'a'.repeat(64),
  url: 'https://stuhelper.example/terms',
};

const validContribution = {
  id: 'contrib-01',
  adapter: 'bhpan',
  revision: 2,
  applied_revision: 1,
  desired_state: 'active',
  state: 'pending',
  reason: '',
  conditions: {
    limit_bytes: 1024,
    personal_reserve: 256,
    until: '2026-12-31T00:00:00Z',
  },
  consent: validTerms,
  accepted_at: '2026-11-18T00:00:00Z',
  created_at: '2026-11-18T00:00:00Z',
  updated_at: '2026-11-18T00:00:00Z',
  observation: {
    observed_at: '2026-11-18T00:00:00Z',
    authorization_expires_at: '2026-12-01T00:00:00Z',
    quota_expires_at: '2026-11-18T01:00:00Z',
    authorized: true,
    used_bytes: 64,
    reserved_bytes: 0,
    available_bytes: 960,
    remaining_replicas: 1,
  },
};

const validPolicy = {
  terms: validTerms,
  adapters: ['bhpan'],
  min_bytes: 1,
  max_bytes: 1048576,
  min_term_seconds: 60,
  max_term_seconds: 86400,
  exit_target_seconds: 3600,
  max_per_owner: 5,
  observation_max_age_seconds: 120,
  renewal_notice_seconds: 604800,
};

const validStatistics = {
  declared_bytes: 1024,
  available_bytes: 960,
  used_bytes: 64,
  reserved_bytes: 0,
  contributions: 1,
  fresh_observations: 1,
  status: 'current',
  generated_at: '2026-11-18T00:00:00Z',
};

describe('sdk/browser.ts runtime contract checks', () => {
  it('parses valid payloads and strips undeclared private fields', () => {
    const parsed = parseContribution({
      ...validContribution,
      instance_id: 'secret-instance',
      credential: 'secret-password',
    });
    assert.equal(parsed.id, 'contrib-01');
    assert.equal('instance_id' in parsed, false);
    assert.equal('credential' in parsed, false);

    assert.equal(parsePolicy(validPolicy).terms.version, 'terms-v1');
    assert.equal(parsePage({ items: [validContribution], next_cursor: '' }).items.length, 1);
    assert.equal(
      parseCandidates({
        items: [{ id: 'cand-1', adapter: 'bhpan', available_bytes: 4096, authorization_expires_at: '2026-12-01T00:00:00+08:00' }],
        next_cursor: '',
      }).items[0]?.id,
      'cand-1',
    );
    assert.equal(parseStatistics(validStatistics).status, 'current');
  });

  it('rejects out-of-range integers, malformed dates, and non-HTTPS or credentialed terms URLs', () => {
    for (const invalid of [
      { ...validContribution, revision: Number.MAX_SAFE_INTEGER + 1 },
      { ...validContribution, revision: 0 },
      { ...validContribution, applied_revision: 3 },
      { ...validContribution, updated_at: '2026-11-18' },
      { ...validContribution, state: 'invented' },
    ]) {
      assert.throws(() => parseContribution(invalid), (err: unknown) => err instanceof ContributionError && err.code === 'incompatible');
    }

    for (const badUrl of ['http://stuhelper.example/terms', 'javascript:alert(1)', 'https://user:pass@stuhelper.example/terms']) {
      assert.throws(
        () => parsePolicy({ ...validPolicy, terms: { ...validTerms, url: badUrl } }),
        (err: unknown) => err instanceof ContributionError && err.code === 'incompatible',
      );
    }

    assert.throws(
      () => parseStatistics({ ...validStatistics, available_bytes: -1 }),
      (err: unknown) => err instanceof ContributionError && err.code === 'incompatible',
    );
  });

  it('maps 400, 401, 403, 404, 409, and 503 distinctly with accurate uncertainty flags', async () => {
    const cases: Array<[number, ContributionError['code'], boolean]> = [
      [400, 'invalid', false],
      [401, 'unauthenticated', false],
      [403, 'forbidden', false],
      [404, 'not_found', false],
      [409, 'conflict', false],
      [503, 'unavailable', true],
    ];
    for (const [status, expectedCode, expectedUncertain] of cases) {
      const api = contributionAPI(async () => new Response('sensitive upstream detail', { status }));
      const op: Operation = { kind: 'retry', key: 'idem-1', id: 'contrib-01', body: { revision: 1 } };
      await assert.rejects(
        () => api.execute(op, new AbortController().signal),
        (err: unknown) => err instanceof ContributionError && err.code === expectedCode && err.uncertain === expectedUncertain,
      );
    }

    const readApi = contributionAPI(async () => new Response('down', { status: 503 }));
    await assert.rejects(
      () => readApi.get(new AbortController().signal, 'contrib-01'),
      (err: unknown) => err instanceof ContributionError && err.code === 'unavailable' && err.uncertain === false,
    );
  });

  it('propagates AbortController cancellation without misreporting network or incompatible errors', async () => {
    let called = false;
    const preAborted = new AbortController();
    const reason = new DOMException('Page unmounted', 'AbortError');
    preAborted.abort(reason);
    const api = contributionAPI(async () => {
      called = true;
      return new Response('{}', { status: 202 });
    });
    await assert.rejects(
      () => api.execute({ kind: 'command', key: 'idem-1', id: 'contrib-01', body: { action: 'pause', revision: 1 } }, preAborted.signal),
      (err: unknown) => err === reason,
    );
    assert.equal(called, false);

    const inFlight = new AbortController();
    const abortReason = new DOMException('Navigated away', 'AbortError');
    const inFlightApi = contributionAPI(async (_input, init) => {
      inFlight.abort(abortReason);
      if (init?.signal?.aborted) throw init.signal.reason;
      return new Response('{}', { status: 200 });
    });
    await assert.rejects(
      () => inFlightApi.policy(inFlight.signal),
      (err: unknown) => err === abortReason,
    );
  });

  it('validates path segments, idempotency keys, and cursors before issuing HTTP requests', async () => {
    let calls = 0;
    const api = contributionAPI(async () => {
      calls++;
      return new Response(JSON.stringify(validContribution), { status: 202 });
    });
    const signal = new AbortController().signal;

    for (const badId of ['', '.', '..', '../admin', 'policy', 'operations', 'statistics', 'options']) {
      await assert.rejects(
        () => api.get(signal, badId),
        (err: unknown) => err instanceof ContributionError && err.code === 'invalid' && err.uncertain === false,
      );
    }
    for (const badOpId of ['', '.', '..', 'a/b']) {
      await assert.rejects(
        () => api.execute({ kind: 'command', key: 'valid-key', id: badOpId, body: { action: 'pause', revision: 1 } }, signal),
        (err: unknown) => err instanceof ContributionError && err.code === 'invalid' && err.uncertain === false,
      );
    }
    await assert.rejects(
      () => api.execute({ kind: 'command', key: 'bad\nkey', id: 'contrib-01', body: { action: 'pause', revision: 1 } }, signal),
      (err: unknown) => err instanceof ContributionError && err.code === 'invalid' && err.uncertain === false,
    );
    await assert.rejects(
      () => api.list(signal, '../bad-cursor'),
      (err: unknown) => err instanceof ContributionError && err.code === 'invalid' && err.uncertain === false,
    );
    assert.equal(calls, 0);
    await api.execute({ kind: 'command', key: 'printable key/space', id: 'contrib-01', body: { action: 'pause', revision: 1 } }, signal);
    assert.equal(calls, 1);
  });
});
