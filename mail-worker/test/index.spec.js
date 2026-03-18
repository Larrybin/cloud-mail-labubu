import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src';
import formService, { FORM_ATTACHMENT_PREFIX, createFormFileSignature } from '../src/service/form-service';
import cryptoUtils from '../src/utils/crypto-utils';
import { encryptFormTenantSecret } from '../src/utils/form-tenant-crypto';
import KvConst from '../src/const/kv-const';

const TEST_FORM_TENANT_KEYRING = env.FORM_TENANT_KEYRING || '{"v1":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}';

async function initDatabase() {
	const req = new Request(`https://mail.example/api/init/${env.jwt_secret}`);
	const ctx = createExecutionContext();
	const resp = await worker.fetch(req, env, ctx);
	await waitOnExecutionContext(ctx);
	expect(resp.status).toBe(200);
}

async function upsertFormTenant({
	brandId = 'demo-brand',
	brandName = 'Demo Brand',
	siteOrigin = 'https://site.example',
	fromEmail = 'no-reply@example.com',
	fromName = 'Labubu',
	toEmail = 'admin@example.com',
	status = 'active',
	resendApiKey = 're_test',
	kid = 'v1'
} = {}) {
	const ciphertext = await encryptFormTenantSecret({
		plaintext: resendApiKey,
		kid,
		keyringRaw: TEST_FORM_TENANT_KEYRING
	});
	await env.db
		.prepare(
			`INSERT INTO form_tenant (
        brand_id, brand_name, site_origin, from_email, from_name, to_email, resend_key_ciphertext, resend_key_kid, status, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(brand_id) DO UPDATE SET
        brand_name = excluded.brand_name,
        site_origin = excluded.site_origin,
        from_email = excluded.from_email,
        from_name = excluded.from_name,
        to_email = excluded.to_email,
        resend_key_ciphertext = excluded.resend_key_ciphertext,
        resend_key_kid = excluded.resend_key_kid,
        status = excluded.status,
        updated_at = CURRENT_TIMESTAMP`,
		)
		.bind(brandId, brandName, siteOrigin, fromEmail, fromName, toEmail, ciphertext, kid, status)
		.run();
}

async function ensureAdminUser(password = 'public-api-password') {
	const { salt, hash } = await cryptoUtils.hashPassword(password);
	await env.db
		.prepare(
			`INSERT OR REPLACE INTO user (user_id, email, type, password, salt, status, is_del)
			 VALUES (1, ?, 1, ?, ?, 0, 0)`,
		)
		.bind(env.admin, hash, salt)
		.run();
}

describe('form api security', () => {
	it('returns 404 on /api/init/:secret when INIT_HTTP_ENABLED is disabled', async () => {
		const req = new Request(`https://mail.example/api/init/${env.jwt_secret}`);
		const disabledEnv = { ...env, INIT_HTTP_ENABLED: 'false' };
		const ctx = createExecutionContext();
		const resp = await worker.fetch(req, disabledEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(resp.status).toBe(404);
	});

	it('returns 401 on /api/form/submit when FORM_API_TOKEN mismatch', async () => {
		const req = new Request('https://mail.example/api/form/submit', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				Authorization: 'Bearer wrong-token'
			},
			body: JSON.stringify({
				type: 'subscribe',
				fromEmail: 'no-reply@example.com',
				fromName: 'Labubu',
				toEmail: 'admin@example.com'
			})
		});
		const env = {
			FORM_API_TOKEN: 'correct-token'
		};
		const ctx = createExecutionContext();
		const resp = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);
		const body = await resp.json();
		expect(resp.status).toBe(401);
		expect(body.code).toBe(401);
	});

	it('returns 413 on /api/form/submit when content-length exceeds limit', async () => {
		const req = new Request('https://mail.example/api/form/submit', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				Authorization: 'Bearer correct-token',
				'content-length': String(64 * 1024 + 1)
			},
			body: JSON.stringify({
				type: 'subscribe',
				fromEmail: 'no-reply@example.com',
				fromName: 'Labubu',
				toEmail: 'admin@example.com'
			})
		});
		const env = {
			FORM_API_TOKEN: 'correct-token',
			FORM_TENANT_KEYRING: TEST_FORM_TENANT_KEYRING
		};
		const ctx = createExecutionContext();
		const resp = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(resp.status).toBe(413);
	});

	it('returns 400 on /api/form/submit when brandId is missing', async () => {
		const req = new Request('https://mail.example/api/form/submit', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				Authorization: 'Bearer correct-token',
				'content-length': '128'
			},
			body: JSON.stringify({
				type: 'subscribe',
				siteOrigin: 'https://site.example'
			})
		});
		const requestEnv = {
			FORM_API_TOKEN: 'correct-token',
			FORM_TENANT_KEYRING: TEST_FORM_TENANT_KEYRING
		};
		const ctx = createExecutionContext();
		const resp = await worker.fetch(req, requestEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(resp.status).toBe(400);
	});

	it('returns 403 on /api/form/submit when payload siteOrigin mismatches tenant origin', async () => {
		await initDatabase();
		await upsertFormTenant({
			brandId: 'demo-brand',
			siteOrigin: 'https://site.example'
		});
		const req = new Request('https://mail.example/api/form/submit', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				Authorization: 'Bearer correct-token',
				'content-length': '128'
			},
			body: JSON.stringify({
				type: 'subscribe',
				brandId: 'demo-brand',
				siteOrigin: 'https://evil.example',
				fromEmail: 'fake@example.com',
				fromName: 'Fake',
				toEmail: 'fake@example.com'
			})
		});
			const requestEnv = {
				...env,
				FORM_API_TOKEN: 'correct-token',
				FORM_TENANT_KEYRING: TEST_FORM_TENANT_KEYRING
			};
			const ctx = createExecutionContext();
			const resp = await worker.fetch(req, requestEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(resp.status).toBe(403);
	});

	it('supports bearer token for /api/public/* and expires token by TTL', async () => {
		await initDatabase();
		const password = 'public-api-password';
		await ensureAdminUser(password);

		const ttlEnv = { ...env, PUBLIC_TOKEN_TTL_SECONDS: '60' };
		const tokenReq = new Request('https://mail.example/api/public/genToken', {
			method: 'POST',
			headers: {
				'content-type': 'application/json'
			},
			body: JSON.stringify({
				email: env.admin,
				password
			})
		});
		const tokenCtx = createExecutionContext();
		const tokenResp = await worker.fetch(tokenReq, ttlEnv, tokenCtx);
		await waitOnExecutionContext(tokenCtx);
		expect(tokenResp.status).toBe(200);
		const tokenBody = await tokenResp.json();
		const publicToken = tokenBody?.data?.token;
		expect(typeof publicToken).toBe('string');

		const listReq = new Request('https://mail.example/api/public/emailList', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				Authorization: `Bearer ${publicToken}`
			},
			body: JSON.stringify({})
		});
		const listCtx = createExecutionContext();
		const listResp = await worker.fetch(listReq, ttlEnv, listCtx);
		await waitOnExecutionContext(listCtx);
		expect(listResp.status).toBe(200);

		await env.kv.delete(KvConst.PUBLIC_KEY);

		const expiredReq = new Request('https://mail.example/api/public/emailList', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				Authorization: `Bearer ${publicToken}`
			},
			body: JSON.stringify({})
		});
		const expiredCtx = createExecutionContext();
		const expiredResp = await worker.fetch(expiredReq, ttlEnv, expiredCtx);
		await waitOnExecutionContext(expiredCtx);
		expect(expiredResp.status).toBe(401);
	});

	it("does not break on apostrophe email for /api/public/addUser", async () => {
		await initDatabase();
		const password = 'public-api-password';
		await ensureAdminUser(password);

		const tokenReq = new Request('https://mail.example/api/public/genToken', {
			method: 'POST',
			headers: {
				'content-type': 'application/json'
			},
			body: JSON.stringify({
				email: env.admin,
				password
			})
		});
		const tokenCtx = createExecutionContext();
		const tokenResp = await worker.fetch(tokenReq, env, tokenCtx);
		await waitOnExecutionContext(tokenCtx);
		expect(tokenResp.status).toBe(200);
		const tokenBody = await tokenResp.json();
		const publicToken = tokenBody?.data?.token;
		expect(typeof publicToken).toBe('string');

		const injectedEmail = `o'hara${Date.now()}@example.com`;
		const addUserReq = new Request('https://mail.example/api/public/addUser', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				Authorization: `Bearer ${publicToken}`
			},
			body: JSON.stringify({
				list: [
					{
						email: injectedEmail,
						password: '123456'
					}
				]
			})
		});
		const addUserCtx = createExecutionContext();
		const addUserResp = await worker.fetch(addUserReq, env, addUserCtx);
		await waitOnExecutionContext(addUserCtx);
		expect(addUserResp.status).toBe(200);

		const userRow = await env.db
			.prepare('SELECT email FROM user WHERE email = ? LIMIT 1')
			.bind(injectedEmail)
			.first();
		expect(userRow?.email).toBe(injectedEmail);
	});
});

describe('form file route integration', () => {
	it('allows /api/form/file without Authorization when signature is valid', async () => {
		const key = `${FORM_ATTACHMENT_PREFIX}ok.pdf`;
		const exp = String(Date.now() + 60_000);
		const sig = await createFormFileSignature({ key, expMs: exp, secret: 'file-secret' });
		const req = new Request(
			`https://mail.example/api/form/file?key=${encodeURIComponent(key)}&exp=${exp}&sig=${sig}`
		);
		const env = {
			FORM_API_TOKEN: 'svc-token',
			FORM_FILE_SECRET: 'file-secret',
			r2: {
				get: async (queryKey) => {
					if (queryKey !== key) return null;
					return {
						body: 'ok-file-body',
						httpEtag: 'etag-1',
						writeHttpMetadata(headers) {
							headers.set('content-type', 'application/pdf');
						}
					};
				}
			}
		};

		const ctx = createExecutionContext();
		const resp = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(resp.status).toBe(200);
		expect(await resp.text()).toBe('ok-file-body');
	});

	it('returns 401 on /api/form/file when signature invalid or expired', async () => {
		const key = `${FORM_ATTACHMENT_PREFIX}bad.pdf`;
		const futureExp = String(Date.now() + 60_000);
		const expiredExp = String(Date.now() - 1_000);
		const expiredSig = await createFormFileSignature({
			key,
			expMs: expiredExp,
			secret: 'file-secret'
		});

		const env = {
			FORM_API_TOKEN: 'svc-token',
			FORM_FILE_SECRET: 'file-secret',
			r2: {
				get: async () => null
			}
		};

		const invalidSigReq = new Request(
			`https://mail.example/api/form/file?key=${encodeURIComponent(key)}&exp=${futureExp}&sig=invalid`
		);
		const invalidSigResp = await worker.fetch(invalidSigReq, env, createExecutionContext());
		expect(invalidSigResp.status).toBe(401);

		const expiredReq = new Request(
			`https://mail.example/api/form/file?key=${encodeURIComponent(key)}&exp=${expiredExp}&sig=${expiredSig}`
		);
		const expiredResp = await worker.fetch(expiredReq, env, createExecutionContext());
		expect(expiredResp.status).toBe(401);
	});
});

describe('form service submit', () => {
	it('supports multipart submit and uploads attachments to form-attachments/ prefix', async () => {
		const uploadedKeys = [];
		const captured = [];
		const formData = new FormData();
		formData.set('type', 'quote');
		formData.set('brandId', 'demo-brand');
		formData.set('siteOrigin', 'https://site.example');
		formData.set('fromEmail', 'ignored@example.com');
		formData.set('fromName', 'Ignored');
		formData.set('toEmail', 'ignored@example.com');
		formData.set('fields', JSON.stringify({ message: 'hello' }));
		formData.append('file_0', new File(['hello'], 'a.pdf', { type: 'application/pdf' }));
		await initDatabase();
		await upsertFormTenant({
			brandId: 'demo-brand',
			siteOrigin: 'https://site.example',
			fromEmail: 'brand-from@example.com',
			fromName: 'Brand Sender',
			toEmail: 'brand-to@example.com'
		});

		const ctx = {
			req: {
				url: 'https://mail.example/api/form/submit',
				header: (name) => {
					if (name === 'content-type') return 'multipart/form-data';
					if (name === 'content-length') return '1024';
					return '';
				},
				formData: async () => formData
			},
			env: {
				db: env.db,
				FORM_TENANT_KEYRING: TEST_FORM_TENANT_KEYRING,
				FORM_FILE_SECRET: 'file-secret',
				r2: {
					put: async (key) => uploadedKeys.push(key)
				},
				FORM_SEND_EMAIL_FN: async (args) => {
					captured.push(args);
					return { data: { id: 'ok' } };
				}
			}
		};

		const result = await formService.submit(ctx);
		expect(result.attachmentCount).toBe(1);
		expect(uploadedKeys.length).toBe(1);
		expect(uploadedKeys[0].startsWith(FORM_ATTACHMENT_PREFIX)).toBe(true);
		expect(captured.length).toBe(1);
		expect(captured[0].payload.fromEmail).toBe('brand-from@example.com');
		expect(captured[0].payload.toEmail).toBe('brand-to@example.com');
	});

	it('routes different brands to different resend keys and from/to addresses', async () => {
		await initDatabase();
		await upsertFormTenant({
			brandId: 'brand-a',
			brandName: 'Brand A',
			siteOrigin: 'https://a.example',
			fromEmail: 'no-reply@a.example',
			toEmail: 'sales@a.example',
			resendApiKey: 're_a'
		});
		await upsertFormTenant({
			brandId: 'brand-b',
			brandName: 'Brand B',
			siteOrigin: 'https://b.example',
			fromEmail: 'no-reply@b.example',
			toEmail: 'sales@b.example',
			resendApiKey: 're_b'
		});

		const calls = [];
		const buildCtx = ({ brandId, siteOrigin }) => ({
			req: {
				url: 'https://mail.example/api/form/submit',
				header: (name) => {
					if (name === 'content-type') return 'application/json';
					if (name === 'content-length') return '256';
					return '';
				},
				json: async () => ({
					type: 'quote',
					brandId,
					siteOrigin,
					fields: { message: 'hello' }
				})
			},
			env: {
				db: env.db,
				FORM_TENANT_KEYRING: TEST_FORM_TENANT_KEYRING,
				FORM_SEND_EMAIL_FN: async (args) => {
					calls.push(args);
					return { data: { id: 'ok' } };
				}
			}
		});

		await formService.submit(buildCtx({ brandId: 'brand-a', siteOrigin: 'https://a.example' }));
		await formService.submit(buildCtx({ brandId: 'brand-b', siteOrigin: 'https://b.example' }));

		expect(calls).toHaveLength(2);
		expect(calls[0].resendApiKey).toBe('re_a');
		expect(calls[0].payload.fromEmail).toBe('no-reply@a.example');
		expect(calls[0].payload.toEmail).toBe('sales@a.example');
		expect(calls[1].resendApiKey).toBe('re_b');
		expect(calls[1].payload.fromEmail).toBe('no-reply@b.example');
		expect(calls[1].payload.toEmail).toBe('sales@b.example');
	});

	it('rolls back uploaded files when send fails', async () => {
		const deletedBatches = [];
		const formData = new FormData();
		formData.set('type', 'quote');
		formData.set('brandId', 'demo-brand');
		formData.set('siteOrigin', 'https://site.example');
		formData.set('fromEmail', 'ignored@example.com');
		formData.set('fromName', 'Ignored');
		formData.set('toEmail', 'ignored@example.com');
		formData.append('file_0', new File(['hello'], 'a.pdf', { type: 'application/pdf' }));
		await initDatabase();
		await upsertFormTenant({
			brandId: 'demo-brand',
			siteOrigin: 'https://site.example'
		});

		const ctx = {
			req: {
				url: 'https://mail.example/api/form/submit',
				header: (name) => {
					if (name === 'content-type') return 'multipart/form-data';
					if (name === 'content-length') return '1024';
					return '';
				},
				formData: async () => formData
			},
			env: {
				db: env.db,
				FORM_TENANT_KEYRING: TEST_FORM_TENANT_KEYRING,
				FORM_FILE_SECRET: 'file-secret',
				r2: {
					put: async () => {},
					delete: async (keys) => deletedBatches.push(keys)
				},
				FORM_SEND_EMAIL_FN: async () => {
					throw new Error('send failed');
				}
			}
		};

		await expect(formService.submit(ctx)).rejects.toThrow('send failed');
		expect(deletedBatches.length).toBe(1);
		expect(Array.isArray(deletedBatches[0])).toBe(true);
		expect(deletedBatches[0][0].startsWith(FORM_ATTACHMENT_PREFIX)).toBe(true);
	});
});

describe('form service file signature guard', () => {
	it('rejects invalid prefix and expired signatures', async () => {
		const invalidPrefixCtx = {
			req: {
				query: (key) => ({ key: 'attachments/a.pdf', exp: '1', sig: 'x' }[key] || '')
			},
			env: {
				FORM_FILE_SECRET: 'secret'
			}
		};
		await expect(formService.getFile(invalidPrefixCtx)).rejects.toMatchObject({ code: 404 });

		const key = `${FORM_ATTACHMENT_PREFIX}expired.pdf`;
		const expiredExp = String(Date.now() - 1000);
		const expiredSig = await createFormFileSignature({ key, expMs: expiredExp, secret: 'secret' });
		const expiredCtx = {
			req: {
				query: (queryKey) => ({ key, exp: expiredExp, sig: expiredSig }[queryKey] || '')
			},
			env: {
				FORM_FILE_SECRET: 'secret'
			}
		};

		await expect(formService.getFile(expiredCtx)).rejects.toMatchObject({ code: 401 });
	});
});
