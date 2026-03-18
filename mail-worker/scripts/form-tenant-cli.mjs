#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import process from 'node:process';
import { encryptFormTenantSecret } from '../src/utils/form-tenant-crypto.js';

function toText(value) {
	return typeof value === 'string' ? value.trim() : '';
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

function normalizeOrigin(input) {
	const raw = toText(input);
	if (!raw) return '';
	try {
		return new URL(raw).origin;
	} catch {
		return '';
	}
}

function escapeSqlValue(value) {
	return String(value).replace(/'/g, "''");
}

function requiredArg(args, key) {
	const value = toText(args[key]);
	if (!value) {
		throw new Error(`Missing required argument: --${key}`);
	}
	return value;
}

function boolFlag(args, key) {
	return String(args[key] || '').toLowerCase() === 'true';
}

function runD1Execute({ database, sql, remote, configPath }) {
	const commandArgs = ['d1', 'execute', database, '--config', configPath, '--command', sql];
	if (remote) commandArgs.push('--remote');
	const result = spawnSync('wrangler', commandArgs, {
		stdio: 'inherit'
	});
	if (result.status !== 0) {
		process.exit(result.status || 1);
	}
}

async function buildCiphertext({ resendApiKey, kid, keyringRaw }) {
	return await encryptFormTenantSecret({
		plaintext: resendApiKey,
		kid,
		keyringRaw
	});
}

function usage() {
	console.log(`Usage:
  node scripts/form-tenant-cli.mjs upsert \\
    --database <d1-database> --brand-id <id> --site-origin <https://site.example> \\
    --from-email <from@example.com> --to-email <to@example.com> --resend-api-key <re_xxx> \\
    --kid <v1> [--brand-name <name>] [--from-name <name>] [--status <active|inactive>] [--config <wrangler.toml>] [--local]

  node scripts/form-tenant-cli.mjs deactivate \\
    --database <d1-database> --brand-id <id> [--config <wrangler.toml>] [--local]

  node scripts/form-tenant-cli.mjs rotate-key \\
    --database <d1-database> --brand-id <id> --resend-api-key <re_xxx> --kid <v2> [--config <wrangler.toml>] [--local]

Env:
  FORM_TENANT_KEYRING  JSON keyring, e.g. {"v1":"<base64-32bytes>","v2":"<base64-32bytes>"}
`);
}

async function main() {
	const args = parseArgs(process.argv.slice(2));
	const command = toText(args._[0]);
	if (!command || boolFlag(args, 'help')) {
		usage();
		return;
	}

	const database = requiredArg(args, 'database');
	const configPath = toText(args.config) || 'wrangler.toml';
	const remote = !boolFlag(args, 'local');
	const keyringRaw = toText(args.keyring) || toText(process.env.FORM_TENANT_KEYRING);

	if (command === 'upsert') {
		const brandId = requiredArg(args, 'brand-id');
		const brandName = toText(args['brand-name']) || brandId;
		const siteOrigin = normalizeOrigin(requiredArg(args, 'site-origin'));
		const fromEmail = requiredArg(args, 'from-email').toLowerCase();
		const toEmail = requiredArg(args, 'to-email').toLowerCase();
		const fromName = toText(args['from-name']) || 'Form';
		const status = toText(args.status).toLowerCase() || 'active';
		const resendApiKey = requiredArg(args, 'resend-api-key');
		const kid = requiredArg(args, 'kid');
		if (!siteOrigin) {
			throw new Error('Invalid --site-origin');
		}
		const ciphertext = await buildCiphertext({ resendApiKey, kid, keyringRaw });
		const sql = `INSERT INTO form_tenant (brand_id, brand_name, site_origin, from_email, from_name, to_email, resend_key_ciphertext, resend_key_kid, status, updated_at)
VALUES ('${escapeSqlValue(brandId)}', '${escapeSqlValue(brandName)}', '${escapeSqlValue(siteOrigin)}', '${escapeSqlValue(fromEmail)}', '${escapeSqlValue(fromName)}', '${escapeSqlValue(toEmail)}', '${escapeSqlValue(ciphertext)}', '${escapeSqlValue(kid)}', '${escapeSqlValue(status)}', CURRENT_TIMESTAMP)
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
		runD1Execute({ database, sql, remote, configPath });
		return;
	}

	if (command === 'deactivate') {
		const brandId = requiredArg(args, 'brand-id');
		const sql = `UPDATE form_tenant
SET status = 'inactive', updated_at = CURRENT_TIMESTAMP
WHERE brand_id = '${escapeSqlValue(brandId)}';`;
		runD1Execute({ database, sql, remote, configPath });
		return;
	}

	if (command === 'rotate-key') {
		const brandId = requiredArg(args, 'brand-id');
		const kid = requiredArg(args, 'kid');
		const resendApiKey = requiredArg(args, 'resend-api-key');
		const ciphertext = await buildCiphertext({ resendApiKey, kid, keyringRaw });
		const sql = `UPDATE form_tenant
SET resend_key_ciphertext = '${escapeSqlValue(ciphertext)}',
    resend_key_kid = '${escapeSqlValue(kid)}',
    updated_at = CURRENT_TIMESTAMP
WHERE brand_id = '${escapeSqlValue(brandId)}';`;
		runD1Execute({ database, sql, remote, configPath });
		return;
	}

	throw new Error(`Unsupported command: ${command}`);
}

main().catch((error) => {
	console.error(error?.message || error);
	process.exit(1);
});
