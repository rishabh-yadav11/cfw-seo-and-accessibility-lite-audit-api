import { describe, it, expect, vi, beforeEach } from 'vitest';
import { isSafeUrl } from '../src/utils/ssrf';
import { authMiddleware } from '../src/utils/auth';
import { rateLimitMiddleware } from '../src/utils/rate-limit';

describe('isSafeUrl', () => {
  it('allows safe external URLs', () => {
    expect(isSafeUrl('https://example.com')).toBe(true);
    expect(isSafeUrl('http://cloudflare.com')).toBe(true);
  });

  it('blocks localhost and internal IPs', () => {
    expect(isSafeUrl('http://localhost')).toBe(false);
    expect(isSafeUrl('http://127.0.0.1')).toBe(false);
    expect(isSafeUrl('http://10.0.0.1')).toBe(false);
    expect(isSafeUrl('http://192.168.1.1')).toBe(false);
    expect(isSafeUrl('http://172.16.0.1')).toBe(false);
  });

  it('blocks internal TLDs', () => {
    expect(isSafeUrl('http://api.internal')).toBe(false);
    expect(isSafeUrl('http://app.local')).toBe(false);
  });

  it('handles invalid URLs gracefully', () => {
    expect(isSafeUrl('not-a-url')).toBe(false);
  });
});

describe('authMiddleware', () => {
  it('returns 401 when no token is configured', async () => {
    const c = { env: {}, req: { header: () => undefined }, json: vi.fn() } as any;
    const next = vi.fn();

    await authMiddleware(c, next);
    expect(c.json).toHaveBeenCalledWith({ error: 'Unauthorized' }, 401);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 401 when auth header is missing', async () => {
    const c = { env: { API_TOKEN: 'secret' }, req: { header: () => undefined }, json: vi.fn() } as any;
    const next = vi.fn();

    await authMiddleware(c, next);
    expect(c.json).toHaveBeenCalledWith({ error: 'Unauthorized' }, 401);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 401 when auth header is incorrect', async () => {
    const c = { env: { API_TOKEN: 'secret' }, req: { header: () => 'Bearer wrong' }, json: vi.fn() } as any;
    const next = vi.fn();

    await authMiddleware(c, next);
    expect(c.json).toHaveBeenCalledWith({ error: 'Unauthorized' }, 401);
    expect(next).not.toHaveBeenCalled();
  });

  it('calls next when auth header is correct', async () => {
    const c = { env: { API_TOKEN: 'secret' }, req: { header: () => 'Bearer secret' }, json: vi.fn() } as any;
    const next = vi.fn();

    await authMiddleware(c, next);
    expect(next).toHaveBeenCalled();
  });
});

describe('rateLimitMiddleware', () => {
  let mockKV: any;

  beforeEach(() => {
    mockKV = {
      get: vi.fn(),
      put: vi.fn(),
    };
  });

  it('calls next directly if no KV is configured', async () => {
    const c = { env: {}, req: { header: () => '1.1.1.1' }, json: vi.fn() } as any;
    const next = vi.fn();

    await rateLimitMiddleware(c, next);
    expect(next).toHaveBeenCalled();
  });

  it('allows request when under limit', async () => {
    mockKV.get.mockResolvedValue('50');
    const c = { env: { RATE_LIMIT_KV: mockKV }, req: { header: () => '1.1.1.1' }, json: vi.fn() } as any;
    const next = vi.fn();

    await rateLimitMiddleware(c, next);
    expect(mockKV.put).toHaveBeenCalledWith('rl:1.1.1.1', '51', { expirationTtl: 60 });
    expect(next).toHaveBeenCalled();
  });

  it('returns 429 when limit is reached', async () => {
    mockKV.get.mockResolvedValue('100');
    const c = { env: { RATE_LIMIT_KV: mockKV }, req: { header: () => '1.1.1.1' }, json: vi.fn() } as any;
    const next = vi.fn();

    await rateLimitMiddleware(c, next);
    expect(c.json).toHaveBeenCalledWith({ error: 'Too Many Requests' }, 429);
    expect(next).not.toHaveBeenCalled();
  });
});
