import { Hono } from 'hono';
const app = new Hono();

import result from '../model/result';
import { cors } from 'hono/cors';

const CORS_ALLOWED_HEADERS = ['Content-Type', 'Authorization', 'accept-language'];
const CORS_ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];

function parseAllowedOrigins(rawValue) {
	return String(rawValue || '')
		.split(',')
		.map(item => item.trim())
		.filter(Boolean);
}

function isPublicPath(path) {
	return path === '/public' ||
		path.startsWith('/public/') ||
		path === '/form' ||
		path.startsWith('/form/');
}

function isSameOrigin(c, origin) {
	try {
		return origin === new URL(c.req.url).origin;
	} catch {
		return false;
	}
}

function resolveOriginByPath(c, origin) {
	if (!origin) return '';
	if (isSameOrigin(c, origin)) return origin;

	const envKey = isPublicPath(c.req.path)
		? 'CORS_PUBLIC_ALLOWED_ORIGINS'
		: 'CORS_ADMIN_ALLOWED_ORIGINS';
	const allowedOrigins = parseAllowedOrigins(c.env?.[envKey]);
	return allowedOrigins.includes(origin) ? origin : '';
}

app.use('*', async (c, next) => {
	const corsMiddleware = cors({
		origin: (origin) => resolveOriginByPath(c, origin),
		allowHeaders: CORS_ALLOWED_HEADERS,
		allowMethods: CORS_ALLOWED_METHODS,
		credentials: true,
		maxAge: 600,
	});
	return corsMiddleware(c, next);
});

app.onError((err, c) => {
	const statusCode = Number.isInteger(err?.code) ? err.code : 500;
	if (err.name === 'BizError') {
		console.log(err.message);
	} else {
		console.error(err);
	}

	if (err.message === `Cannot read properties of undefined (reading 'get')`) {
		return c.json(result.fail('KV数据库未绑定 KV database not bound', 502), 502);
	}

	if (err.message === `Cannot read properties of undefined (reading 'put')`) {
		return c.json(result.fail('KV数据库未绑定 KV database not bound', 502), 502);
	}

	if (err.message === `Cannot read properties of undefined (reading 'prepare')`) {
		return c.json(result.fail('D1数据库未绑定 D1 database not bound', 502), 502);
	}

	return c.json(result.fail(err.message, statusCode), statusCode);
});

export default app;
