import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import worker from '../src';
import { encryptFormTenantSecret } from '../src/utils/form-tenant-crypto';

const ADMIN_HEADER = { Authorization: `Bearer ${env.ADMIN_API_TOKEN}` };
const TEST_FORM_TENANT_KEYRING = env.FORM_TENANT_KEYRING || '{"v1":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}';

async function fetchWorker(request, requestEnv = env) {
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, requestEnv, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

async function initDatabase() {
	const response = await fetchWorker(new Request(`https://mail.example/api/init/${env.jwt_secret}`));
	expect(response.status).toBe(200);
}

function jsonRequest(url, { method = 'POST', token = env.ADMIN_API_TOKEN, body = {} } = {}) {
	return new Request(url, {
		method,
		headers: {
			'content-type': 'application/json',
			Authorization: `Bearer ${token}`,
		},
		body: JSON.stringify(body),
	});
}

async function upsertFormTenant(brandId, siteOrigin) {
	const ciphertext = await encryptFormTenantSecret({
		plaintext: 're_test_inquiry',
		kid: 'v1',
		keyringRaw: TEST_FORM_TENANT_KEYRING,
	});
	await env.db
		.prepare(
			`INSERT INTO form_tenant (
        brand_id, brand_name, site_origin, from_email, from_name, to_email, resend_key_ciphertext, resend_key_kid, status, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'v1', 'active', CURRENT_TIMESTAMP)
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
		.bind(
			brandId,
			'Inquiry Brand',
			siteOrigin,
			'no-reply@example.com',
			'Inquiry Brand',
			'sales@example.com',
			ciphertext,
		)
		.run();
}

describe('Labubu admin api', () => {
	it('requires ADMIN_API_TOKEN for admin endpoints', async () => {
		const response = await fetchWorker(new Request('https://mail.example/api/admin/cf-accounts'));
		expect(response.status).toBe(401);
	});

	it('supports cf account CRUD and preserves blank secrets on update', async () => {
		await initDatabase();
		const suffix = crypto.randomUUID();
		const createResponse = await fetchWorker(
			jsonRequest('https://mail.example/api/admin/cf-accounts', {
				body: {
					name: 'Sub Account',
					cfAccountId: `cf-${suffix}`,
					cfApiToken: 'cfut_test_secret',
					resendApiKey: 're_test_secret',
					bridgeToken: 'bridge_secret',
					domains: 'example.com',
					note: 'first',
				},
			}),
		);
		expect(createResponse.status).toBe(200);
		const created = await createResponse.json();
		const id = created.data.id;
		expect(created.data.cfApiToken).toBe('');

		const maskedResponse = await fetchWorker(
			new Request('https://mail.example/api/admin/cf-accounts', { headers: ADMIN_HEADER }),
		);
		const maskedBody = await maskedResponse.json();
		const masked = maskedBody.data.find((item) => item.id === id);
		expect(masked.cfApiToken).toContain('******');

		const unmaskedResponse = await fetchWorker(
			new Request('https://mail.example/api/admin/cf-accounts?unmasked=true', { headers: ADMIN_HEADER }),
		);
		const unmaskedBody = await unmaskedResponse.json();
		expect(unmaskedBody.data.find((item) => item.id === id).cfApiToken).toBe('cfut_test_secret');

		const updateResponse = await fetchWorker(
			jsonRequest(`https://mail.example/api/admin/cf-accounts/${id}`, {
				method: 'PUT',
				body: {
					name: 'Sub Account Updated',
					cfAccountId: `cf-${suffix}`,
					cfApiToken: '',
					resendApiKey: '',
					bridgeToken: '',
					domains: 'example.org',
					note: 'updated',
				},
			}),
		);
		expect(updateResponse.status).toBe(200);

		const afterUpdateResponse = await fetchWorker(
			new Request('https://mail.example/api/admin/cf-accounts?unmasked=true', { headers: ADMIN_HEADER }),
		);
		const afterUpdateBody = await afterUpdateResponse.json();
		const afterUpdate = afterUpdateBody.data.find((item) => item.id === id);
		expect(afterUpdate.name).toBe('Sub Account Updated');
		expect(afterUpdate.cfApiToken).toBe('cfut_test_secret');

		const deleteResponse = await fetchWorker(
			new Request(`https://mail.example/api/admin/cf-accounts/${id}`, {
				method: 'DELETE',
				headers: ADMIN_HEADER,
			}),
		);
		expect(deleteResponse.status).toBe(200);
	});

	it('stores form submissions as inquiries and exposes summary data', async () => {
		await initDatabase();
		const brandId = `inquiry-${crypto.randomUUID()}`;
		const siteOrigin = 'https://inquiry.example';
		await upsertFormTenant(brandId, siteOrigin);

		const payload = {
			type: 'quote',
			brandId,
			siteOrigin,
			fields: {
				name: 'Buyer One',
				email: 'buyer@example.com',
				company: 'Buyer Co',
				message: 'Need 200 units',
			},
		};
		const body = JSON.stringify(payload);
		const submitResponse = await fetchWorker(
			new Request('https://mail.example/api/form/submit', {
				method: 'POST',
				headers: {
					'content-type': 'application/json',
					'content-length': String(new TextEncoder().encode(body).byteLength),
					Authorization: `Bearer ${env.FORM_API_TOKEN}`,
				},
				body,
			}),
			{
				...env,
				FORM_SEND_EMAIL_FN: async () => ({ data: { id: 'sent' } }),
			},
		);
		expect(submitResponse.status).toBe(200);

		const listResponse = await fetchWorker(
			new Request(`https://mail.example/api/form/inquiries?brandId=${brandId}&keyword=Buyer`, {
				headers: ADMIN_HEADER,
			}),
		);
		expect(listResponse.status).toBe(200);
		const listBody = await listResponse.json();
		expect(listBody.data.total).toBe(1);
		const inquiry = listBody.data.list[0];
		expect(inquiry.name).toBe('Buyer One');
		expect(inquiry.email).toBe('buyer@example.com');
		expect(inquiry.attachments).toEqual([]);

		const statusResponse = await fetchWorker(
			jsonRequest(`https://mail.example/api/form/inquiries/${inquiry.id}/status`, {
				method: 'PATCH',
				body: { status: 'read' },
			}),
		);
		expect(statusResponse.status).toBe(200);
		const statusBody = await statusResponse.json();
		expect(statusBody.data.status).toBe('read');

		const summaryResponse = await fetchWorker(
			new Request('https://mail.example/api/admin/cloud-mail/summary', { headers: ADMIN_HEADER }),
		);
		expect(summaryResponse.status).toBe(200);
		const summaryBody = await summaryResponse.json();
		expect(summaryBody.data.connected).toBe(true);
		expect(summaryBody.data.inquiryTotal).toBeGreaterThanOrEqual(1);
		expect(summaryBody.data.tenantTotal).toBeGreaterThanOrEqual(1);
		expect(Array.isArray(summaryBody.data.recentInquiries)).toBe(true);
	});
});
