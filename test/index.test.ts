import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import app from '../src/index';

const MOCK_API_TOKEN = 'test-token';
const MOCK_ENV = {
  API_TOKEN: MOCK_API_TOKEN,
  RATE_LIMIT_KV: {
    get: vi.fn(),
    put: vi.fn(),
  },
  AUDIT_RESULTS_R2: {
    get: vi.fn(),
    put: vi.fn(),
  },
};

const createMockFetchResponse = (text: string, headers: Record<string, string> = {}) => ({
  text: vi.fn().mockResolvedValue(text),
  headers: new Headers(headers),
});

describe('API Route Integrations', () => {
  let originalFetch: any;

  beforeEach(() => {
    // Reset KV & R2 mocks
    vi.mocked(MOCK_ENV.RATE_LIMIT_KV.get).mockReset();
    vi.mocked(MOCK_ENV.RATE_LIMIT_KV.put).mockReset();
    vi.mocked(MOCK_ENV.AUDIT_RESULTS_R2.get).mockReset();
    vi.mocked(MOCK_ENV.AUDIT_RESULTS_R2.put).mockReset();

    // Stub global fetch
    originalFetch = (globalThis as any).fetch;
    (globalThis as any).fetch = vi.fn();
  });

  afterEach(() => {
    (globalThis as any).fetch = originalFetch;
  });

  const makeRequest = async (url: string, method = 'POST', body?: any, token: string | null = MOCK_API_TOKEN) => {
    const headers = new Headers();
    headers.set('Content-Type', 'application/json');
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    const req = new Request(`http://localhost${url}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const envObj = {
      API_TOKEN: MOCK_API_TOKEN,
      RATE_LIMIT_KV: MOCK_ENV.RATE_LIMIT_KV,
      AUDIT_RESULTS_R2: MOCK_ENV.AUDIT_RESULTS_R2
    };
    return app.fetch(req, envObj);
  };

  it('security baseline: rejects missing auth', async () => {
    const res = await makeRequest('/audit', 'POST', { url: 'https://example.com' }, null);
    expect(res.status).toBe(401);
  });

  it('security baseline: applies rate limiting', async () => {
    vi.mocked(MOCK_ENV.RATE_LIMIT_KV.get).mockResolvedValue('100');
    const res = await makeRequest('/audit', 'POST', { url: 'https://example.com' });
    expect(res.status).toBe(429);
  });

  it('security baseline: blocks SSRF', async () => {
    const res = await makeRequest('/audit', 'POST', { url: 'http://127.0.0.1/admin' });
    expect(res.status).toBe(403);
  });

  it('happy_path: returns issue list with severity and fix hint', async () => {
    const mockHtml = `<html><body><h1>Title 1</h1><h1>Title 2</h1></body></html>`;
    vi.mocked((globalThis as any).fetch).mockResolvedValue(createMockFetchResponse(mockHtml) as any);

    const res = await makeRequest('/audit', 'POST', { url: 'https://example.com' });
    expect(res.status).toBe(200);

    const data = await res.json() as any;
    expect(data.issues).toBeDefined();
    expect(Array.isArray(data.issues)).toBe(true);
    expect(data.issues.length).toBeGreaterThan(0);
    expect(data.issues[0]).toHaveProperty('severity');
    expect(data.issues[0]).toHaveProperty('hint');

    // Verify R2 mock was called
    expect(MOCK_ENV.AUDIT_RESULTS_R2.put).toHaveBeenCalled();
  });

  it('malformed_html: returns partial results, not 500', async () => {
    const mockHtml = `<html><head><title>Unclosed</head><body><p><<malformed>></body></html>`;
    vi.mocked((globalThis as any).fetch).mockResolvedValue(createMockFetchResponse(mockHtml) as any);

    const res = await makeRequest('/audit', 'POST', { url: 'https://example.com/malformed' });
    expect(res.status).toBe(200);

    const data = await res.json() as any;
    expect(data.partial_parse).toBe(true);
    expect(data.issues).toBeDefined();
    expect(Array.isArray(data.issues)).toBe(true);
  });

  it('oversized_page: returns 413 or partial_parse flag', async () => {
    // Mock fetch to simulate a large response via Content-Length header
    vi.mocked((globalThis as any).fetch).mockResolvedValue(createMockFetchResponse('', {
      'content-length': (6 * 1024 * 1024).toString(), // 6MB
    }) as any);

    const res = await makeRequest('/audit', 'POST', { url: 'https://example.com/huge' });
    expect(res.status).toBe(413);
  });
});
