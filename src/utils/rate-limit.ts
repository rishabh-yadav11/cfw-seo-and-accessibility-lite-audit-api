import { Context, Next } from 'hono';

export async function rateLimitMiddleware(c: Context, next: Next) {
  const kv = c.env?.RATE_LIMIT_KV as any; // any to avoid TS errors without specific types package installed or imported correctly here for the test
  
  if (!kv) {
    return await next();
  }

  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const key = `rl:${ip}`;

  const current = await kv.get(key);
  const count = current ? parseInt(current, 10) : 0;

  if (count >= 100) {
    return c.json({ error: 'Too Many Requests' }, 429);
  }

  await kv.put(key, (count + 1).toString(), { expirationTtl: 60 });
  await next();
}
