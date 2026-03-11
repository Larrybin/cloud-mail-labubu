import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src';
import formService, { FORM_ATTACHMENT_PREFIX, createFormFileSignature } from '../src/service/form-service';

describe('form api security', () => {
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
			FORM_ALLOWED_TO_EMAILS: 'admin@example.com',
			FORM_RESEND_API_KEY: 're_test'
		};
		const ctx = createExecutionContext();
		const resp = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(resp.status).toBe(413);
	});

	it('returns 403 on /api/form/submit when toEmail is outside allowlist', async () => {
		const req = new Request('https://mail.example/api/form/submit', {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				Authorization: 'Bearer correct-token',
				'content-length': '128'
			},
			body: JSON.stringify({
				type: 'subscribe',
				fromEmail: 'no-reply@example.com',
				fromName: 'Labubu',
				toEmail: 'other@example.com'
			})
		});
		const env = {
			FORM_API_TOKEN: 'correct-token',
			FORM_ALLOWED_TO_EMAILS: 'admin@example.com',
			FORM_RESEND_API_KEY: 're_test'
		};
		const ctx = createExecutionContext();
		const resp = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(resp.status).toBe(403);
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
		const formData = new FormData();
		formData.set('type', 'quote');
		formData.set('siteOrigin', 'https://site.example');
		formData.set('fromEmail', 'no-reply@example.com');
		formData.set('fromName', 'Labubu');
		formData.set('toEmail', 'admin@example.com');
		formData.set('fields', JSON.stringify({ message: 'hello' }));
		formData.append('file_0', new File(['hello'], 'a.pdf', { type: 'application/pdf' }));

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
				FORM_RESEND_API_KEY: 're_test',
				FORM_ALLOWED_TO_EMAILS: 'admin@example.com',
				FORM_FILE_SECRET: 'file-secret',
				r2: {
					put: async (key) => uploadedKeys.push(key)
				},
				FORM_SEND_EMAIL_FN: async () => ({ data: { id: 'ok' } })
			}
		};

		const result = await formService.submit(ctx);
		expect(result.attachmentCount).toBe(1);
		expect(uploadedKeys.length).toBe(1);
		expect(uploadedKeys[0].startsWith(FORM_ATTACHMENT_PREFIX)).toBe(true);
	});

	it('rolls back uploaded files when send fails', async () => {
		const deletedBatches = [];
		const formData = new FormData();
		formData.set('type', 'quote');
		formData.set('siteOrigin', 'https://site.example');
		formData.set('fromEmail', 'no-reply@example.com');
		formData.set('fromName', 'Labubu');
		formData.set('toEmail', 'admin@example.com');
		formData.append('file_0', new File(['hello'], 'a.pdf', { type: 'application/pdf' }));

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
				FORM_RESEND_API_KEY: 're_test',
				FORM_ALLOWED_TO_EMAILS: 'admin@example.com',
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
