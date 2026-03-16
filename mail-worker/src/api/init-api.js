import app from '../hono/hono';
import { dbInit } from '../init/init';

app.get('/init/:secret', (c) => {
	const enabled = String(c.env.INIT_HTTP_ENABLED || '').trim().toLowerCase() === 'true';
	if (!enabled) {
		return c.text('Not Found', 404);
	}
	return dbInit.init(c);
})
