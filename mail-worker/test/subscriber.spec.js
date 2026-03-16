import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src';
import jwtUtils from '../src/utils/jwt-utils';
import KvConst from '../src/const/kv-const';

function buildSubscribeRequest(payload) {
	const body = JSON.stringify(payload);
	const contentLength = String(new TextEncoder().encode(body).byteLength);
	return new Request('https://mail.example/api/subscriber/subscribe', {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			'content-length': contentLength,
			Authorization: `Bearer ${env.FORM_API_TOKEN}`,
		},
		body,
	});
}

async function initDatabase() {
	const req = new Request(`https://mail.example/api/init/${env.jwt_secret}`);
	const ctx = createExecutionContext();
	const resp = await worker.fetch(req, env, ctx);
	await waitOnExecutionContext(ctx);
	expect(resp.status).toBe(200);
}

async function createAdminAuthHeader() {
	await env.db
		.prepare(
			`INSERT OR IGNORE INTO user (email, type, password, salt, status, is_del)
       VALUES (?, 1, 'x', 'x', 0, 0)`,
		)
		.bind(env.admin)
		.run();

	const userRow = await env.db
		.prepare(`SELECT user_id FROM user WHERE email = ? COLLATE NOCASE LIMIT 1`)
		.bind(env.admin)
		.first();
	const userId = Number(userRow?.user_id || 0);
	const rawToken = `subscriber-test-${Date.now()}`;
	const jwt = await jwtUtils.generateToken({ env }, { userId, token: rawToken }, 3600);

	await env.kv.put(
		`${KvConst.AUTH_INFO}${userId}`,
		JSON.stringify({
			user: { userId, email: env.admin },
			tokens: [rawToken],
			refreshTime: new Date().toISOString(),
		}),
	);

	return jwt;
}

describe('subscriber api', () => {
	it('creates subscriber records and keeps repeat subscribe idempotent', async () => {
		await initDatabase();

		const payload = {
			listKey: 'demo-brand',
			email: 'User@Example.com',
			brandId: 'demo-brand',
			brandName: 'Demo Brand',
			siteOrigin: 'https://demo.example',
			locale: 'en',
			sourcePath: '/en/product/demo-hat/',
			sourceType: 'website_subscribe_form',
		};

		const firstReq = buildSubscribeRequest(payload);
		const firstCtx = createExecutionContext();
		const firstResp = await worker.fetch(firstReq, env, firstCtx);
		await waitOnExecutionContext(firstCtx);
		expect(firstResp.status).toBe(200);

		const secondReq = buildSubscribeRequest({ ...payload, email: 'user@example.com' });
		const secondCtx = createExecutionContext();
		const secondResp = await worker.fetch(secondReq, env, secondCtx);
		await waitOnExecutionContext(secondCtx);
		expect(secondResp.status).toBe(200);

		const countRow = await env.db
			.prepare(
				`SELECT COUNT(*) AS total FROM subscriber WHERE list_key = ? AND normalized_email = ?`,
			)
			.bind('demo-brand', 'user@example.com')
			.first();
		expect(Number(countRow?.total || 0)).toBe(1);

		const eventRow = await env.db
			.prepare(
				`SELECT COUNT(*) AS total FROM subscriber_event
         WHERE subscriber_id = (
           SELECT subscriber_id FROM subscriber WHERE list_key = ? AND normalized_email = ?
         )`,
			)
			.bind('demo-brand', 'user@example.com')
			.first();
		expect(Number(eventRow?.total || 0)).toBe(2);
	});

	it('supports authenticated list and export queries', async () => {
		await initDatabase();
		const authHeader = await createAdminAuthHeader();

		const subscribeReq = buildSubscribeRequest({
			listKey: 'export-brand',
			email: 'viewer@example.com',
			brandId: 'export-brand',
			brandName: 'Export Brand',
			siteOrigin: 'https://demo.example',
			locale: 'fr',
			sourcePath: '/fr/',
			sourceType: 'website_subscribe_form',
		});
		const subscribeCtx = createExecutionContext();
		await worker.fetch(subscribeReq, env, subscribeCtx);
		await waitOnExecutionContext(subscribeCtx);

		const listReq = new Request(
			'https://mail.example/api/subscriber/list?keyword=viewer&listKey=export-brand&status=subscribed&page=1&size=10',
			{
				headers: { Authorization: authHeader },
			},
		);
		const listCtx = createExecutionContext();
		const listResp = await worker.fetch(listReq, env, listCtx);
		await waitOnExecutionContext(listCtx);
		expect(listResp.status).toBe(200);
		const listBody = await listResp.json();
		expect(listBody.data.list).toHaveLength(1);
		expect(listBody.data.list[0].email).toBe('viewer@example.com');

		const exportReq = new Request(
			'https://mail.example/api/subscriber/export?listKey=export-brand&status=subscribed',
			{
				headers: { Authorization: authHeader },
			},
		);
		const exportCtx = createExecutionContext();
		const exportResp = await worker.fetch(exportReq, env, exportCtx);
		await waitOnExecutionContext(exportCtx);
		expect(exportResp.status).toBe(200);
		expect(exportResp.headers.get('content-type')).toContain('text/csv');
		const csv = await exportResp.text();
		expect(csv).toContain('viewer@example.com');
		expect(csv).toContain('export-brand');
	});

	it('rejects subscribe payloads that exceed body size limit', async () => {
		await initDatabase();

		const req = new Request('https://mail.example/api/subscriber/subscribe', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				'content-length': String(64 * 1024 + 1),
				Authorization: `Bearer ${env.FORM_API_TOKEN}`,
			},
			body: JSON.stringify({
				listKey: 'limit-brand',
				email: 'limit@example.com',
			}),
		});
		const ctx = createExecutionContext();
		const resp = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(resp.status).toBe(413);
	});

	it('requires valid content-length on subscribe requests', async () => {
		await initDatabase();

		const missingLengthReq = new Request('https://mail.example/api/subscriber/subscribe', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				Authorization: `Bearer ${env.FORM_API_TOKEN}`,
			},
			body: JSON.stringify({
				listKey: 'limit-brand',
				email: 'missing-length@example.com',
			}),
		});
		const missingCtx = createExecutionContext();
		const missingResp = await worker.fetch(missingLengthReq, env, missingCtx);
		await waitOnExecutionContext(missingCtx);
		expect(missingResp.status).toBe(411);

		const invalidLengthReq = new Request('https://mail.example/api/subscriber/subscribe', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				'content-length': 'invalid',
				Authorization: `Bearer ${env.FORM_API_TOKEN}`,
			},
			body: JSON.stringify({
				listKey: 'limit-brand',
				email: 'invalid-length@example.com',
			}),
		});
		const invalidCtx = createExecutionContext();
		const invalidResp = await worker.fetch(invalidLengthReq, env, invalidCtx);
		await waitOnExecutionContext(invalidCtx);
		expect(invalidResp.status).toBe(400);
	});

	it('normalizes subscribe metadata and prevents csv formula injection on export', async () => {
		await initDatabase();
		const authHeader = await createAdminAuthHeader();

		const subscribeReq = buildSubscribeRequest({
			listKey: 'formula-brand',
			email: 'formula@example.com',
			brandId: 'formula-brand',
			brandName: ' =cmd',
			siteOrigin: 'javascript:alert(1)',
			locale: '  zh-CN\r\n',
			sourcePath: '@evil-path',
			sourceType: '+danger\0',
		});
		const subscribeCtx = createExecutionContext();
		const subscribeResp = await worker.fetch(subscribeReq, env, subscribeCtx);
		await waitOnExecutionContext(subscribeCtx);
		expect(subscribeResp.status).toBe(200);

		const row = await env.db
			.prepare(
				`SELECT brand_name, site_origin, locale, source_path, source_type
         FROM subscriber
         WHERE list_key = ? AND normalized_email = ?`,
			)
			.bind('formula-brand', 'formula@example.com')
			.first();
		expect(row.brand_name).toBe('=cmd');
		expect(row.site_origin).toBe('');
		expect(row.locale).toBe('zh-CN');
		expect(row.source_path).toBe('/@evil-path');
		expect(row.source_type).toBe('+danger');

		const exportReq = new Request(
			'https://mail.example/api/subscriber/export?listKey=formula-brand&status=subscribed',
			{
				headers: { Authorization: authHeader },
			},
		);
		const exportCtx = createExecutionContext();
		const exportResp = await worker.fetch(exportReq, env, exportCtx);
		await waitOnExecutionContext(exportCtx);
		expect(exportResp.status).toBe(200);
		const csv = await exportResp.text();
		expect(csv).toContain("'=cmd");
		expect(csv).toContain("'+danger");
		expect(csv).toContain('/@evil-path');
		expect(csv).not.toContain('javascript:alert(1)');
	});

	it('rejects export when size exceeds limit', async () => {
		await initDatabase();
		const authHeader = await createAdminAuthHeader();

		const req = new Request(
			'https://mail.example/api/subscriber/export?size=5001',
			{ headers: { Authorization: authHeader } },
		);
		const ctx = createExecutionContext();
		const resp = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(resp.status).toBe(400);
	});
});
