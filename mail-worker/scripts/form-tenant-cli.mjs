#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { encryptFormTenantSecret } from '../src/utils/form-tenant-crypto.js';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ACTIONS = new Set(['upsert', 'get', 'set-status', 'rotate-key']);

function toText(value) {
	return typeof value === 'string' ? value.trim() : '';
}

function toOptionalLower(value) {
	return toText(value).toLowerCase();
}

function parseArgs(argv) {
	const args = { _: [] };
	for (let i = 0; i < argv.length; i += 1) {
		const item = argv[i];
		if (!item.startsWith('--')) {
			args._.push(item);
			continue;
		}
		const key = item.slice(2);
		const next = argv[i + 1];
		if (!next || next.startsWith('--')) {
			args[key] = 'true';
			continue;
		}
		args[key] = next;
		i += 1;
	}
	return args;
}

function createCliError(message, code = 'E_TENANT_CLI') {
	const error = new Error(message);
	error.code = code;
	return error;
}

function normalizeOrigin(value, { label, required = true } = {}) {
	const raw = toText(value);
	if (!raw) {
		if (!required) return '';
		throw createCliError(`${label || 'siteOrigin'} 不能为空`, 'E_VALIDATE');
	}
	try {
		return new URL(raw).origin.toLowerCase();
	} catch {
		throw createCliError(`${label || 'siteOrigin'} 不是合法 URL：${raw}`, 'E_VALIDATE');
	}
}

function normalizeEmail(value, { label, required = true } = {}) {
	const email = toOptionalLower(value);
	if (!email) {
		if (!required) return '';
		throw createCliError(`${label || 'email'} 不能为空`, 'E_VALIDATE');
	}
	if (!EMAIL_REGEX.test(email)) {
		throw createCliError(`${label || 'email'} 不是合法邮箱：${email}`, 'E_VALIDATE');
	}
	return email;
}

function normalizeStatus(value, { required = true } = {}) {
	const status = toOptionalLower(value);
	if (!status) {
		if (!required) return '';
		throw createCliError('status 不能为空（active|inactive）', 'E_VALIDATE');
	}
	if (status !== 'active' && status !== 'inactive') {
		throw createCliError(`status 非法：${status}（仅支持 active|inactive）`, 'E_VALIDATE');
	}
	return status;
}

function normalizeKid(value, { required = true } = {}) {
	const kid = toText(value);
	if (!kid) {
		if (!required) return '';
		throw createCliError('kid 不能为空', 'E_VALIDATE');
	}
	return kid;
}

function normalizeBrandId(value, { required = true } = {}) {
	const brandId = toText(value);
	if (!brandId) {
		if (!required) return '';
		throw createCliError('brandId 不能为空', 'E_VALIDATE');
	}
	return brandId;
}

function parseRequestJson(raw) {
	const text = toText(raw);
	if (!text) {
		throw createCliError('缺少 --request-json', 'E_ARG');
	}
	try {
		const parsed = JSON.parse(text);
		if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
			throw new Error('request-json 必须是对象');
		}
		return parsed;
	} catch (error) {
		throw createCliError(`--request-json 不是合法 JSON：${String(error?.message || error)}`, 'E_ARG');
	}
}

function parseJsonOutput(raw, { label }) {
	const text = String(raw || '').trim();
	if (!text) {
		throw createCliError(`${label} 返回空输出`, 'E_D1');
	}
	try {
		return JSON.parse(text);
	} catch {
		// ignore
	}
	const lines = text
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean);
	for (let index = lines.length - 1; index >= 0; index -= 1) {
		try {
			return JSON.parse(lines[index]);
		} catch {
			// ignore and keep trying
		}
	}
	throw createCliError(`${label} 返回非 JSON`, 'E_D1');
}

function extractRows(payload, output = []) {
	if (Array.isArray(payload)) {
		for (const item of payload) {
			extractRows(item, output);
		}
		return output;
	}
	if (!payload || typeof payload !== 'object') {
		return output;
	}
	if (Array.isArray(payload.results)) {
		for (const row of payload.results) {
			if (row && typeof row === 'object' && !Array.isArray(row)) {
				output.push(row);
			}
		}
	}
	if (Array.isArray(payload.rows)) {
		for (const row of payload.rows) {
			if (row && typeof row === 'object' && !Array.isArray(row)) {
				output.push(row);
			}
		}
	}
	if (payload.result) extractRows(payload.result, output);
	if (payload.data) extractRows(payload.data, output);
	return output;
}

function boolValue(value, fallback) {
	if (typeof value === 'boolean') return value;
	const raw = toOptionalLower(value);
	if (!raw) return fallback;
	if (raw === 'true' || raw === '1' || raw === 'yes') return true;
	if (raw === 'false' || raw === '0' || raw === 'no') return false;
	return fallback;
}

function escapeSqlValue(value) {
	return String(value).replace(/'/g, "''");
}

function formatSpawnFailure({ command, args, result }) {
	const stderr = String(result?.stderr || '').trim();
	const stdout = String(result?.stdout || '').trim();
	const chunks = [`wrangler 执行失败：${command} ${args.join(' ')}`];
	if (stderr) chunks.push(`stderr=${stderr}`);
	if (stdout) chunks.push(`stdout=${stdout}`);
	return chunks.join(' | ');
}

function runD1Execute({ database, sql, remote, configPath, spawnSyncImpl }) {
	const commandArgs = ['d1', 'execute', database, '--config', configPath, '--command', sql, '--json'];
	if (remote) commandArgs.push('--remote');
	const result = spawnSyncImpl('wrangler', commandArgs, {
		encoding: 'utf8'
	});
	if (result?.error) {
		throw createCliError(`wrangler 执行异常：${String(result.error?.message || result.error)}`, 'E_D1');
	}
	if (result?.status !== 0) {
		throw createCliError(formatSpawnFailure({ command: 'wrangler', args: commandArgs, result }), 'E_D1');
	}
	return parseJsonOutput(result.stdout, { label: 'wrangler d1 execute' });
}

function mapTenantRow(row) {
	if (!row || typeof row !== 'object') return null;
	return {
		brandId: normalizeBrandId(row.brand_id, { required: false }),
		brandName: toText(row.brand_name),
		siteOrigin: normalizeOrigin(row.site_origin, { label: 'site_origin', required: false }),
		fromEmail: normalizeEmail(row.from_email, { label: 'from_email', required: false }),
		fromName: toText(row.from_name) || 'Form',
		toEmail: normalizeEmail(row.to_email, { label: 'to_email', required: false }),
		resendKeyCiphertext: toText(row.resend_key_ciphertext),
		resendKeyKid: toText(row.resend_key_kid),
		status: normalizeStatus(row.status || 'inactive', { required: false }) || 'inactive'
	};
}

function normalizeUpsertRequest(request) {
	const tenant = request?.tenant;
	if (!tenant || typeof tenant !== 'object' || Array.isArray(tenant)) {
		throw createCliError('upsert 缺少 tenant 对象', 'E_VALIDATE');
	}
	const brandId = normalizeBrandId(tenant.brandId);
	const brandName = toText(tenant.brandName) || brandId;
	const siteOrigin = normalizeOrigin(tenant.siteOrigin, { label: 'tenant.siteOrigin' });
	const fromEmail = normalizeEmail(tenant.fromEmail, { label: 'tenant.fromEmail' });
	const toEmail = normalizeEmail(tenant.toEmail || tenant.contactEmail, { label: 'tenant.toEmail' });
	const fromName = toText(tenant.fromName) || 'Form';
	const status = normalizeStatus(request.status || tenant.status || 'active');
	const resendApiKey = toText(request.resendApiKey || request.resendKey);
	const kid = normalizeKid(request.kid || tenant.kid, { required: Boolean(resendApiKey) });

	return {
		brandId,
		brandName,
		siteOrigin,
		fromEmail,
		toEmail,
		fromName,
		status,
		resendApiKey,
		kid
	};
}

function normalizeRequestWithBrandAndOrigin(request, { requireStatus = false } = {}) {
	const brandId = normalizeBrandId(request?.brandId);
	const siteOrigin = normalizeOrigin(request?.siteOrigin, { label: 'siteOrigin' });
	const status = requireStatus ? normalizeStatus(request?.status) : '';
	return { brandId, siteOrigin, status };
}

async function readDatabaseFromWrangler({ configPath, readFileImpl }) {
	const resolvedPath = path.resolve(process.cwd(), configPath);
	let source = '';
	try {
		source = await readFileImpl(resolvedPath, 'utf8');
	} catch {
		return '';
	}
	const lines = String(source || '').split(/\r?\n/);
	let inBlock = false;
	let databaseName = '';
	let databaseId = '';
	for (const line of lines) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith('#')) continue;
		if (trimmed.startsWith('[[')) {
			if (inBlock && (databaseName || databaseId)) {
				return databaseName || databaseId;
			}
			inBlock = trimmed === '[[d1_databases]]';
			databaseName = '';
			databaseId = '';
			continue;
		}
		if (!inBlock) continue;
		const match = /^([A-Za-z_]+)\s*=\s*"(.*)"\s*$/.exec(trimmed);
		if (!match) continue;
		if (match[1] === 'database_name') databaseName = toText(match[2]);
		if (match[1] === 'database_id') databaseId = toText(match[2]);
	}
	if (inBlock) {
		return databaseName || databaseId;
	}
	return '';
}

async function resolveRuntime({ request, env, readFileImpl }) {
	const configPath = toText(request?.configPath || env.CLOUD_MAIL_WRANGLER_CONFIG) || 'wrangler.toml';
	const remote = boolValue(request?.remote, true);
	const keyringRaw = toText(request?.keyring || env.FORM_TENANT_KEYRING);
	const database =
		toText(request?.database || env.CLOUD_MAIL_D1_DATABASE || env.D1_DATABASE) ||
		(await readDatabaseFromWrangler({ configPath, readFileImpl }));
	if (!database) {
		throw createCliError(
			'缺少 database：请在 request-json 传 database，或配置 CLOUD_MAIL_D1_DATABASE，或在 wrangler.toml 配置 [[d1_databases]].database_name',
			'E_ARG'
		);
	}
	return {
		database,
		configPath,
		remote,
		keyringRaw
	};
}

async function queryTenantByBrandId({ runtime, brandId, spawnSyncImpl }) {
	const sql = `SELECT brand_id, brand_name, site_origin, from_email, from_name, to_email, resend_key_ciphertext, resend_key_kid, status
FROM form_tenant
WHERE brand_id = '${escapeSqlValue(brandId)}'
LIMIT 1;`;
	const payload = runD1Execute({
		database: runtime.database,
		sql,
		remote: runtime.remote,
		configPath: runtime.configPath,
		spawnSyncImpl
	});
	const row = extractRows(payload)[0] || null;
	return mapTenantRow(row);
}

async function queryTenantByBrandAndOrigin({ runtime, brandId, siteOrigin, spawnSyncImpl }) {
	const sql = `SELECT brand_id, brand_name, site_origin, from_email, from_name, to_email, resend_key_ciphertext, resend_key_kid, status
FROM form_tenant
WHERE brand_id = '${escapeSqlValue(brandId)}'
  AND site_origin = '${escapeSqlValue(siteOrigin)}'
LIMIT 1;`;
	const payload = runD1Execute({
		database: runtime.database,
		sql,
		remote: runtime.remote,
		configPath: runtime.configPath,
		spawnSyncImpl
	});
	const row = extractRows(payload)[0] || null;
	return mapTenantRow(row);
}

function normalizeTenantResponse(tenant) {
	return {
		brandId: tenant.brandId,
		brandName: tenant.brandName,
		siteOrigin: tenant.siteOrigin,
		fromEmail: tenant.fromEmail,
		fromName: tenant.fromName,
		toEmail: tenant.toEmail,
		status: tenant.status
	};
}

function createActionResult(action, tenant) {
	return {
		ok: true,
		action,
		tenant: normalizeTenantResponse(tenant),
		kid: toText(tenant?.resendKeyKid)
	};
}

async function actionGet({ request, runtime, spawnSyncImpl }) {
	const { brandId, siteOrigin } = normalizeRequestWithBrandAndOrigin(request);
	const tenant = await queryTenantByBrandAndOrigin({ runtime, brandId, siteOrigin, spawnSyncImpl });
	if (!tenant) {
		throw createCliError(`tenant 不存在：brandId=${brandId} siteOrigin=${siteOrigin}`, 'E_NOT_FOUND');
	}
	return createActionResult('get', tenant);
}

async function actionSetStatus({ request, runtime, spawnSyncImpl }) {
	const { brandId, siteOrigin, status } = normalizeRequestWithBrandAndOrigin(request, {
		requireStatus: true
	});
	const existing = await queryTenantByBrandAndOrigin({ runtime, brandId, siteOrigin, spawnSyncImpl });
	if (!existing) {
		throw createCliError(`tenant 不存在：brandId=${brandId} siteOrigin=${siteOrigin}`, 'E_NOT_FOUND');
	}

	const sql = `UPDATE form_tenant
SET status = '${escapeSqlValue(status)}',
    updated_at = CURRENT_TIMESTAMP
WHERE brand_id = '${escapeSqlValue(brandId)}'
  AND site_origin = '${escapeSqlValue(siteOrigin)}';`;
	runD1Execute({
		database: runtime.database,
		sql,
		remote: runtime.remote,
		configPath: runtime.configPath,
		spawnSyncImpl
	});

	const tenant = await queryTenantByBrandAndOrigin({ runtime, brandId, siteOrigin, spawnSyncImpl });
	if (!tenant) {
		throw createCliError(`set-status 后租户读回失败：brandId=${brandId}`, 'E_D1');
	}
	if (tenant.status !== status) {
		throw createCliError(
			`set-status 读回校验失败：expect=${status} actual=${tenant.status || ''}`,
			'E_D1'
		);
	}
	return createActionResult('set-status', tenant);
}

async function actionRotateKey({ request, runtime, spawnSyncImpl, encryptSecret }) {
	const { brandId, siteOrigin } = normalizeRequestWithBrandAndOrigin(request);
	const resendApiKey = toText(request?.resendApiKey || request?.resendKey);
	const kid = normalizeKid(request?.kid);
	if (!resendApiKey) {
		throw createCliError('rotate-key 缺少 resendApiKey', 'E_VALIDATE');
	}
	if (!runtime.keyringRaw) {
		throw createCliError('缺少 FORM_TENANT_KEYRING，无法加密 resend key', 'E_VALIDATE');
	}

	const existing = await queryTenantByBrandAndOrigin({ runtime, brandId, siteOrigin, spawnSyncImpl });
	if (!existing) {
		throw createCliError(`tenant 不存在：brandId=${brandId} siteOrigin=${siteOrigin}`, 'E_NOT_FOUND');
	}

	const ciphertext = await encryptSecret({
		plaintext: resendApiKey,
		kid,
		keyringRaw: runtime.keyringRaw
	});
	const sql = `UPDATE form_tenant
SET resend_key_ciphertext = '${escapeSqlValue(ciphertext)}',
    resend_key_kid = '${escapeSqlValue(kid)}',
    updated_at = CURRENT_TIMESTAMP
WHERE brand_id = '${escapeSqlValue(brandId)}'
  AND site_origin = '${escapeSqlValue(siteOrigin)}';`;
	runD1Execute({
		database: runtime.database,
		sql,
		remote: runtime.remote,
		configPath: runtime.configPath,
		spawnSyncImpl
	});

	const tenant = await queryTenantByBrandAndOrigin({ runtime, brandId, siteOrigin, spawnSyncImpl });
	if (!tenant) {
		throw createCliError(`rotate-key 后租户读回失败：brandId=${brandId}`, 'E_D1');
	}
	if (tenant.resendKeyKid !== kid) {
		throw createCliError(`rotate-key 读回校验失败：expect kid=${kid} actual=${tenant.resendKeyKid}`, 'E_D1');
	}
	return createActionResult('rotate-key', tenant);
}

async function actionUpsert({ request, runtime, spawnSyncImpl, encryptSecret }) {
	const normalized = normalizeUpsertRequest(request);
	const existing = await queryTenantByBrandId({
		runtime,
		brandId: normalized.brandId,
		spawnSyncImpl
	});

	if (!normalized.resendApiKey && !existing) {
		throw createCliError('upsert 新租户必须提供 resendApiKey 与 kid', 'E_VALIDATE');
	}
	if (!normalized.resendApiKey && existing) {
		if (!existing.resendKeyCiphertext || !existing.resendKeyKid) {
			throw createCliError(
				'upsert 发现租户密钥不完整：请提供 resendApiKey + kid 以重建密钥',
				'E_VALIDATE'
			);
		}
	}

	if (normalized.resendApiKey) {
		if (!runtime.keyringRaw) {
			throw createCliError('缺少 FORM_TENANT_KEYRING，无法加密 resend key', 'E_VALIDATE');
		}
		const ciphertext = await encryptSecret({
			plaintext: normalized.resendApiKey,
			kid: normalized.kid,
			keyringRaw: runtime.keyringRaw
		});
		const sql = `INSERT INTO form_tenant (brand_id, brand_name, site_origin, from_email, from_name, to_email, resend_key_ciphertext, resend_key_kid, status, updated_at)
VALUES ('${escapeSqlValue(normalized.brandId)}', '${escapeSqlValue(normalized.brandName)}', '${escapeSqlValue(normalized.siteOrigin)}', '${escapeSqlValue(normalized.fromEmail)}', '${escapeSqlValue(normalized.fromName)}', '${escapeSqlValue(normalized.toEmail)}', '${escapeSqlValue(ciphertext)}', '${escapeSqlValue(normalized.kid)}', '${escapeSqlValue(normalized.status)}', CURRENT_TIMESTAMP)
ON CONFLICT(brand_id) DO UPDATE SET
  brand_name = excluded.brand_name,
  site_origin = excluded.site_origin,
  from_email = excluded.from_email,
  from_name = excluded.from_name,
  to_email = excluded.to_email,
  resend_key_ciphertext = excluded.resend_key_ciphertext,
  resend_key_kid = excluded.resend_key_kid,
  status = excluded.status,
  updated_at = CURRENT_TIMESTAMP;`;
		runD1Execute({
			database: runtime.database,
			sql,
			remote: runtime.remote,
			configPath: runtime.configPath,
			spawnSyncImpl
		});
	} else {
		const sql = `UPDATE form_tenant
SET brand_name = '${escapeSqlValue(normalized.brandName)}',
    site_origin = '${escapeSqlValue(normalized.siteOrigin)}',
    from_email = '${escapeSqlValue(normalized.fromEmail)}',
    from_name = '${escapeSqlValue(normalized.fromName)}',
    to_email = '${escapeSqlValue(normalized.toEmail)}',
    status = '${escapeSqlValue(normalized.status)}',
    updated_at = CURRENT_TIMESTAMP
WHERE brand_id = '${escapeSqlValue(normalized.brandId)}';`;
		runD1Execute({
			database: runtime.database,
			sql,
			remote: runtime.remote,
			configPath: runtime.configPath,
			spawnSyncImpl
		});
	}

	const tenant = await queryTenantByBrandAndOrigin({
		runtime,
		brandId: normalized.brandId,
		siteOrigin: normalized.siteOrigin,
		spawnSyncImpl
	});
	if (!tenant) {
		throw createCliError(
			`upsert 后租户读回失败：brandId=${normalized.brandId} siteOrigin=${normalized.siteOrigin}`,
			'E_D1'
		);
	}
	if (tenant.status !== normalized.status) {
		throw createCliError(
			`upsert 读回校验失败：status expect=${normalized.status} actual=${tenant.status || ''}`,
			'E_D1'
		);
	}
	if (normalized.resendApiKey && tenant.resendKeyKid !== normalized.kid) {
		throw createCliError(
			`upsert 读回校验失败：kid expect=${normalized.kid} actual=${tenant.resendKeyKid || ''}`,
			'E_D1'
		);
	}
	return createActionResult('upsert', tenant);
}

export function usageText() {
	return `Usage:
  pnpm tenant:config --action <upsert|get|set-status|rotate-key> --request-json '<json>'

request-json fields:
  Common:
    database?   D1 database name or id (fallback: CLOUD_MAIL_D1_DATABASE or wrangler.toml [[d1_databases]].database_name)
    configPath? Wrangler config path (default: wrangler.toml)
    remote?     Use remote D1 execution (default: true)
    keyring?    FORM_TENANT_KEYRING override

  upsert:
    {
      "tenant": {
        "brandId": "...",
        "brandName": "...",
        "siteOrigin": "https://site.example",
        "fromEmail": "from@example.com",
        "fromName": "Form",
        "toEmail": "to@example.com" // or contactEmail
      },
      "status": "active|inactive",
      "resendApiKey": "re_xxx", // optional when tenant already exists
      "kid": "v1"               // required when resendApiKey is provided
    }

  get:
    {"brandId":"...","siteOrigin":"https://site.example"}

  set-status:
    {"brandId":"...","siteOrigin":"https://site.example","status":"active|inactive"}

  rotate-key:
    {"brandId":"...","siteOrigin":"https://site.example","resendApiKey":"re_xxx","kid":"v2"}
`;
}

export async function runTenantCli({
	argv = process.argv.slice(2),
	env = process.env,
	spawnSyncImpl,
	encryptSecret = encryptFormTenantSecret,
	readFileImpl = fs.readFile
} = {}) {
	if (typeof spawnSyncImpl !== 'function') {
		throw createCliError('缺少 spawnSyncImpl 执行器', 'E_ARG');
	}
	const args = parseArgs(argv);
	const action = toText(args.action);
	if (args.help || args.h) {
		return { ok: true, help: true, usage: usageText() };
	}
	if (!action || !ACTIONS.has(action)) {
		throw createCliError(`--action 非法，必须是 ${Array.from(ACTIONS).join('|')}`, 'E_ARG');
	}
	const request = parseRequestJson(args['request-json']);
	const runtime = await resolveRuntime({ request, env, readFileImpl });

	if (action === 'upsert') {
		return await actionUpsert({ request, runtime, spawnSyncImpl, encryptSecret });
	}
	if (action === 'get') {
		return await actionGet({ request, runtime, spawnSyncImpl });
	}
	if (action === 'set-status') {
		return await actionSetStatus({ request, runtime, spawnSyncImpl });
	}
	if (action === 'rotate-key') {
		return await actionRotateKey({ request, runtime, spawnSyncImpl, encryptSecret });
	}
	throw createCliError(`不支持的 action: ${action}`, 'E_ARG');
}

function toErrorPayload(error) {
	return {
		ok: false,
		error: {
			code: toText(error?.code) || 'E_TENANT_CLI',
			message: toText(error?.message) || String(error)
		}
	};
}

export async function runCliMain({
	argv = process.argv.slice(2),
	env = process.env,
	stdout = process.stdout,
	stderr = process.stderr,
	spawnSyncImpl,
	encryptSecret = encryptFormTenantSecret,
	readFileImpl = fs.readFile
} = {}) {
	try {
		let resolvedSpawnSync = spawnSyncImpl;
		if (typeof resolvedSpawnSync !== 'function') {
			const childProcessModule = await import('node:child_process');
			resolvedSpawnSync = childProcessModule.spawnSync;
		}
		const result = await runTenantCli({
			argv,
			env,
			spawnSyncImpl: resolvedSpawnSync,
			encryptSecret,
			readFileImpl
		});
		if (result?.help) {
			stdout.write(`${result.usage}\n`);
			return 0;
		}
		stdout.write(`${JSON.stringify(result)}\n`);
		return 0;
	} catch (error) {
		stderr.write(`${JSON.stringify(toErrorPayload(error))}\n`);
		return 1;
	}
}

async function main() {
	const exitCode = await runCliMain();
	process.exit(exitCode);
}

const directRunUrl = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : '';
if (directRunUrl && import.meta.url === directRunUrl) {
	main();
}
