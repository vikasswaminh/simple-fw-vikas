import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { api, ApiError } from './client';

// Capture the last fetch call for assertion. Typed to match the fetch
// signature so vi.fn().mock.calls indexes correctly.
type FetchArgs = Parameters<typeof fetch>;
function mockFetch(response: {
  status?: number;
  ok?: boolean;
  json?: unknown;
  text?: string;
}) {
  return vi.fn<FetchArgs, Promise<Response>>(async () => ({
    ok: response.ok ?? true,
    status: response.status ?? 200,
    statusText: response.status === 401 ? 'Unauthorized' : 'OK',
    json: async () => response.json ?? {},
    text: async () => response.text ?? '',
  } as unknown as Response));
}

// Helper: pull the RequestInit out of a fetch call without TS friction.
function callInit<T extends ReturnType<typeof mockFetch>>(m: T, n = 0): RequestInit {
  return (m.mock.calls[n]?.[1] ?? {}) as RequestInit;
}

describe('ApiClient — CSRF double-submit header', () => {
  beforeEach(() => {
    // Start each test with a fresh document.cookie state.
    document.cookie = 'quickfw_csrf=; path=/; max-age=0';
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('does NOT send X-CSRF-Token on GET (safe method)', async () => {
    document.cookie = 'quickfw_csrf=abc123; path=/';
    const fetchMock = mockFetch({ json: { ok: true } });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await api.get('/api/whatever');

    expect(fetchMock).toHaveBeenCalledOnce();
    const headers = callInit(fetchMock).headers as Record<string, string>;
    expect(headers['X-CSRF-Token']).toBeUndefined();
  });

  it('sends X-CSRF-Token on POST when cookie is present', async () => {
    document.cookie = 'quickfw_csrf=abc123; path=/';
    const fetchMock = mockFetch({ json: { ok: true } });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await api.post('/api/firewall', { rules: [] });

    const opts = callInit(fetchMock);
    const headers = opts.headers as Record<string, string>;
    expect(headers['X-CSRF-Token']).toBe('abc123');
    expect(opts.method).toBe('POST');
  });

  it('omits X-CSRF-Token on POST when no cookie is present', async () => {
    // No csrf cookie set → no header. The backend will 403 — the client just
    // hands off whatever it has.
    const fetchMock = mockFetch({ json: { ok: true } });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await api.post('/api/firewall', { rules: [] });

    const headers = callInit(fetchMock).headers as Record<string, string>;
    expect(headers['X-CSRF-Token']).toBeUndefined();
  });

  it('sends the header on PUT and DELETE as well', async () => {
    document.cookie = 'quickfw_csrf=xyz789; path=/';
    const fetchMock = mockFetch({ json: {} });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await api.delete('/api/nat/snat/1');
    let headers = callInit(fetchMock, 0).headers as Record<string, string>;
    expect(headers['X-CSRF-Token']).toBe('xyz789');

    await api.put('/api/thing/1', { x: 1 });
    headers = callInit(fetchMock, 1).headers as Record<string, string>;
    expect(headers['X-CSRF-Token']).toBe('xyz789');
  });

  it('picks the right cookie value when multiple cookies are present', async () => {
    document.cookie = 'other=value; path=/';
    document.cookie = 'quickfw_csrf=the-csrf; path=/';
    document.cookie = 'still_more=junk; path=/';
    const fetchMock = mockFetch({ json: {} });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await api.post('/api/firewall', {});

    const headers = callInit(fetchMock).headers as Record<string, string>;
    expect(headers['X-CSRF-Token']).toBe('the-csrf');
  });
});

describe('ApiClient — error handling', () => {
  afterEach(() => vi.restoreAllMocks());

  it('throws ApiError with status on non-OK response', async () => {
    globalThis.fetch = mockFetch({
      ok: false,
      status: 403,
      json: { error: 'forbidden' },
    }) as unknown as typeof fetch;

    await expect(api.post('/api/firewall', {})).rejects.toBeInstanceOf(ApiError);
    try {
      await api.post('/api/firewall', {});
    } catch (e) {
      expect((e as ApiError).status).toBe(403);
    }
  });
});
