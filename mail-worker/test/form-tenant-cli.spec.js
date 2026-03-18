import { describe, expect, it, vi } from 'vitest';
import { runTenantCli } from '../scripts/form-tenant-cli.mjs';

function jsonResultRows(rows = []) {
	return {
		status: 0,
		stdout: JSON.stringify([{ success: true, results: rows, meta: { changes: rows.length } }]),
		stderr: ''
	};
}

function jsonResultWrite(changes = 1) {
	return {
		status: 0,
		stdout: JSON.stringify([{ success: true, results: [], meta: { changes } }]),
		stderr: ''
	};
}

function createSpawnQueue(responses) {
	let index = 0;
	return vi.fn(() => {
		const current = responses[index];
		index += 1;
		if (typeof current === 'function') return current();
		if (!current) {
			return {
				status: 1,
				stdout: '',
				stderr: 'unexpected call'
			};
		}
		return current;
	});
}

function getSqlFromCall(call) {
	const args = call?.[1] || [];
	const sqlIndex = args.indexOf('--command');
	return sqlIndex >= 0 ? args[sqlIndex + 1] : '';
}

describe('form tenant cli', () => {
	it('upsert（带 key）成功并返回读回 JSON', async () => {
		const spawnSyncImpl = createSpawnQueue([
			jsonResultRows([]),
			jsonResultWrite(1),
			jsonResultRows([
				{
					brand_id: 'water-filter-co',
					brand_name: 'Water Filter Co',
					site_origin: 'https://water-filter.co',
					from_email: 'support@water-filter.co',
					from_name: 'Water Filter Co',
					to_email: 'sales@water-filter.co',
					resend_key_kid: 'v1',
					status: 'active'
				}
			])
		]);
		const encryptSecret = vi.fn(async () => 'ciphertext_v1');

		const result = await runTenantCli({
			argv: [
				'--action',
				'upsert',
				'--request-json',
				JSON.stringify({
					database: 'mail-db',
					remote: false,
					tenant: {
						brandId: 'water-filter-co',
						brandName: 'Water Filter Co',
						siteOrigin: 'https://water-filter.co/path?q=1',
						fromEmail: 'support@water-filter.co',
						fromName: 'Water Filter Co',
						contactEmail: 'sales@water-filter.co'
					},
					status: 'active',
					resendApiKey: 're_test_xxx',
					kid: 'v1'
				})
			],
			env: {
				FORM_TENANT_KEYRING: '{"v1":"test"}'
			},
			spawnSyncImpl,
			encryptSecret
		});

		expect(result.ok).toBe(true);
		expect(result.action).toBe('upsert');
		expect(result.tenant.toEmail).toBe('sales@water-filter.co');
		expect(result.kid).toBe('v1');
		expect(encryptSecret).toHaveBeenCalledTimes(1);
		expect(spawnSyncImpl).toHaveBeenCalledTimes(3);
		expect(spawnSyncImpl.mock.calls[1][1]).toContain('--json');
		expect(getSqlFromCall(spawnSyncImpl.mock.calls[1])).toContain('INSERT INTO form_tenant');
		expect(getSqlFromCall(spawnSyncImpl.mock.calls[1])).toContain('ciphertext_v1');
	});

	it('upsert（无 key）仅更新非密钥字段，且要求已有租户', async () => {
		const spawnSyncImpl = createSpawnQueue([
			jsonResultRows([
				{
					brand_id: 'water-filter-co',
					brand_name: 'Water Filter Co',
					site_origin: 'https://water-filter.co',
					from_email: 'support@water-filter.co',
					from_name: 'Water Filter Co',
					to_email: 'support@water-filter.co',
					resend_key_ciphertext: 'ciphertext_v1',
					resend_key_kid: 'v1',
					status: 'active'
				}
			]),
			jsonResultWrite(1),
			jsonResultRows([
				{
					brand_id: 'water-filter-co',
					brand_name: 'WF Sales',
					site_origin: 'https://water-filter.co',
					from_email: 'noreply@water-filter.co',
					from_name: 'Sales',
					to_email: 'sales@water-filter.co',
					resend_key_kid: 'v1',
					status: 'inactive'
				}
			])
		]);
		const encryptSecret = vi.fn(async () => 'ciphertext_should_not_call');

		const result = await runTenantCli({
			argv: [
				'--action',
				'upsert',
				'--request-json',
				JSON.stringify({
					database: 'mail-db',
					tenant: {
						brandId: 'water-filter-co',
						brandName: 'WF Sales',
						siteOrigin: 'https://water-filter.co',
						fromEmail: 'noreply@water-filter.co',
						fromName: 'Sales',
						toEmail: 'sales@water-filter.co'
					},
					status: 'inactive'
				})
			],
			spawnSyncImpl,
			encryptSecret
		});

		expect(result.ok).toBe(true);
		expect(result.tenant.status).toBe('inactive');
		expect(encryptSecret).not.toHaveBeenCalled();
		const updateSql = getSqlFromCall(spawnSyncImpl.mock.calls[1]);
		expect(updateSql).toContain('UPDATE form_tenant');
		expect(updateSql).not.toContain('resend_key_ciphertext');
	});

	it('upsert（无 key）遇到坏数据（缺密钥）必须失败并提示重建', async () => {
		const spawnSyncImpl = createSpawnQueue([
			jsonResultRows([
				{
					brand_id: 'water-filter-co',
					brand_name: 'Water Filter Co',
					site_origin: 'https://water-filter.co',
					from_email: 'support@water-filter.co',
					from_name: 'Water Filter Co',
					to_email: 'support@water-filter.co',
					resend_key_ciphertext: '',
					resend_key_kid: '',
					status: 'active'
				}
			])
		]);

		await expect(
			runTenantCli({
				argv: [
					'--action',
					'upsert',
					'--request-json',
					JSON.stringify({
						database: 'mail-db',
						tenant: {
							brandId: 'water-filter-co',
							brandName: 'WF Sales',
							siteOrigin: 'https://water-filter.co',
							fromEmail: 'noreply@water-filter.co',
							fromName: 'Sales',
							toEmail: 'sales@water-filter.co'
						},
						status: 'inactive'
					})
				],
				spawnSyncImpl
			})
		).rejects.toThrow(/请提供 resendApiKey \+ kid/);
		expect(spawnSyncImpl).toHaveBeenCalledTimes(1);
	});

	it('upsert 新租户无 key 时失败', async () => {
		const spawnSyncImpl = createSpawnQueue([jsonResultRows([])]);

		await expect(
			runTenantCli({
				argv: [
					'--action',
					'upsert',
					'--request-json',
					JSON.stringify({
						database: 'mail-db',
						tenant: {
							brandId: 'water-filter-co',
							brandName: 'WF',
							siteOrigin: 'https://water-filter.co',
							fromEmail: 'noreply@water-filter.co',
							toEmail: 'sales@water-filter.co'
						},
						status: 'active'
					})
				],
				spawnSyncImpl
			})
		).rejects.toThrow(/新租户必须提供 resendApiKey/);
	});

	it('get 返回 tenant + kid', async () => {
		const spawnSyncImpl = createSpawnQueue([
			jsonResultRows([
				{
					brand_id: 'water-filter-co',
					brand_name: 'WF',
					site_origin: 'https://water-filter.co',
					from_email: 'noreply@water-filter.co',
					from_name: 'WF',
					to_email: 'sales@water-filter.co',
					resend_key_kid: 'v3',
					status: 'active'
				}
			])
		]);

		const result = await runTenantCli({
			argv: [
				'--action',
				'get',
				'--request-json',
				JSON.stringify({
					database: 'mail-db',
					brandId: 'water-filter-co',
					siteOrigin: 'https://water-filter.co/a/b'
				})
			],
			spawnSyncImpl
		});

		expect(result.ok).toBe(true);
		expect(result.action).toBe('get');
		expect(result.tenant.siteOrigin).toBe('https://water-filter.co');
		expect(result.kid).toBe('v3');
	});

	it('set-status 读回校验通过', async () => {
		const spawnSyncImpl = createSpawnQueue([
			jsonResultRows([
				{
					brand_id: 'water-filter-co',
					brand_name: 'WF',
					site_origin: 'https://water-filter.co',
					from_email: 'noreply@water-filter.co',
					from_name: 'WF',
					to_email: 'sales@water-filter.co',
					resend_key_kid: 'v1',
					status: 'active'
				}
			]),
			jsonResultWrite(1),
			jsonResultRows([
				{
					brand_id: 'water-filter-co',
					brand_name: 'WF',
					site_origin: 'https://water-filter.co',
					from_email: 'noreply@water-filter.co',
					from_name: 'WF',
					to_email: 'sales@water-filter.co',
					resend_key_kid: 'v1',
					status: 'inactive'
				}
			])
		]);

		const result = await runTenantCli({
			argv: [
				'--action',
				'set-status',
				'--request-json',
				JSON.stringify({
					database: 'mail-db',
					brandId: 'water-filter-co',
					siteOrigin: 'https://water-filter.co',
					status: 'inactive'
				})
			],
			spawnSyncImpl
		});

		expect(result.ok).toBe(true);
		expect(result.action).toBe('set-status');
		expect(result.tenant.status).toBe('inactive');
	});

	it('rotate-key 会加密并更新 kid', async () => {
		const spawnSyncImpl = createSpawnQueue([
			jsonResultRows([
				{
					brand_id: 'water-filter-co',
					brand_name: 'WF',
					site_origin: 'https://water-filter.co',
					from_email: 'noreply@water-filter.co',
					from_name: 'WF',
					to_email: 'sales@water-filter.co',
					resend_key_kid: 'v1',
					status: 'active'
				}
			]),
			jsonResultWrite(1),
			jsonResultRows([
				{
					brand_id: 'water-filter-co',
					brand_name: 'WF',
					site_origin: 'https://water-filter.co',
					from_email: 'noreply@water-filter.co',
					from_name: 'WF',
					to_email: 'sales@water-filter.co',
					resend_key_kid: 'v2',
					status: 'active'
				}
			])
		]);
		const encryptSecret = vi.fn(async () => 'ciphertext_v2');

		const result = await runTenantCli({
			argv: [
				'--action',
				'rotate-key',
				'--request-json',
				JSON.stringify({
					database: 'mail-db',
					brandId: 'water-filter-co',
					siteOrigin: 'https://water-filter.co',
					resendApiKey: 're_new',
					kid: 'v2'
				})
			],
			env: {
				FORM_TENANT_KEYRING: '{"v2":"test"}'
			},
			spawnSyncImpl,
			encryptSecret
		});

		expect(result.ok).toBe(true);
		expect(result.action).toBe('rotate-key');
		expect(result.kid).toBe('v2');
		expect(encryptSecret).toHaveBeenCalledTimes(1);
	});
});
