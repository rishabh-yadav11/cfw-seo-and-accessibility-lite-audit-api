import { Context, Next } from 'hono';

export async function authMiddleware(c: Context, next: Next) {
  const token = c.env?.API_TOKEN;
  const authHeader = c.req.header('Authorization');

  // Skip auth for options requests or whatever if needed, but not here
  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  if (authHeader !== `Bearer ${token}`) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  await next();
}
