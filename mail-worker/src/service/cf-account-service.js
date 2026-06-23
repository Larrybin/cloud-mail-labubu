import BizError from '../error/biz-error';

function toText(value) {
	return typeof value === 'string' ? value.trim() : '';
}

function toBoolInt(value) {
	return value === true || value === 1 || value === '1' ? 1 : 0;
}

function isBlankSecret(value) {
	const text = toText(value);
	return !text || text.includes('*');
}

function maskSecret(value) {
	const text = toText(value);
	if (!text) return '';
	if (text.length <= 12) return `${text.slice(0, 4)}******`;
	return `${text.slice(0, 8)}******${text.slice(-4)}`;
}

function mapAccount(row, { unmasked = false, detail = false } = {}) {
	if (!row) return null;
	return {
		id: Number(row.id),
		name: toText(row.name),
		cfAccountId: toText(row.cf_account_id),
		cfApiToken: detail ? '' : unmasked ? toText(row.cf_api_token) : maskSecret(row.cf_api_token),
		resendApiKey: detail ? '' : unmasked ? toText(row.resend_api_key) : maskSecret(row.resend_api_key),
		bridgeToken: detail ? '' : unmasked ? toText(row.bridge_token) : maskSecret(row.bridge_token),
		domains: toText(row.domains),
		note: toText(row.note),
		isPrimary: Number(row.is_primary || 0) === 1,
		status: toText(row.status) || 'active',
		createdAt: toText(row.created_at),
		updatedAt: toText(row.updated_at)
	};
}

function assertDb(c) {
	if (!c?.env?.db || typeof c.env.db.prepare !== 'function') {
		throw new BizError('D1 is not configured', 503);
	}
	return c.env.db;
}

function normalizeInput(payload, existing = null) {
	const name = toText(payload?.name);
	const cfAccountId = toText(payload?.cfAccountId);
	if (!name) throw new BizError('name is required', 400);
	if (!cfAccountId) throw new BizError('cfAccountId is required', 400);
	if (!existing && !toText(payload?.cfApiToken)) throw new BizError('cfApiToken is required', 400);

	return {
		name,
		cfAccountId,
		cfApiToken: isBlankSecret(payload?.cfApiToken) && existing ? existing.cf_api_token : toText(payload?.cfApiToken),
		resendApiKey: isBlankSecret(payload?.resendApiKey) && existing ? existing.resend_api_key : toText(payload?.resendApiKey),
		bridgeToken: isBlankSecret(payload?.bridgeToken) && existing ? existing.bridge_token : toText(payload?.bridgeToken),
		domains: toText(payload?.domains),
		note: toText(payload?.note),
		isPrimary: toBoolInt(payload?.isPrimary),
		status: toText(payload?.status) || 'active'
	};
}

const cfAccountService = {
	async list(c, params = {}) {
		const unmasked = String(params.unmasked || '').toLowerCase() === 'true';
		const result = await assertDb(c)
			.prepare(
				`SELECT *
         FROM cf_account
         ORDER BY is_primary DESC, id ASC`,
			)
			.all();
		const rows = Array.isArray(result?.results) ? result.results : [];
		return rows.map(row => mapAccount(row, { unmasked }));
	},

	async detail(c, idInput) {
		const id = Number(idInput);
		const row = await assertDb(c)
			.prepare(`SELECT * FROM cf_account WHERE id = ? LIMIT 1`)
			.bind(id)
			.first();
		if (!row) throw new BizError('CF account not found', 404);
		return mapAccount(row, { detail: true });
	},

	async create(c, payload) {
		const account = normalizeInput(payload);
		const row = await assertDb(c)
			.prepare(
				`INSERT INTO cf_account (
          name, cf_account_id, cf_api_token, resend_api_key, bridge_token, domains, note, is_primary, status, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        RETURNING *`,
			)
			.bind(
				account.name,
				account.cfAccountId,
				account.cfApiToken,
				account.resendApiKey,
				account.bridgeToken,
				account.domains,
				account.note,
				account.isPrimary,
				account.status,
			)
			.first();
		return mapAccount(row, { detail: true });
	},

	async update(c, idInput, payload) {
		const id = Number(idInput);
		const existing = await assertDb(c)
			.prepare(`SELECT * FROM cf_account WHERE id = ? LIMIT 1`)
			.bind(id)
			.first();
		if (!existing) throw new BizError('CF account not found', 404);

		const account = normalizeInput(payload, existing);
		const row = await assertDb(c)
			.prepare(
				`UPDATE cf_account
         SET name = ?,
             cf_account_id = ?,
             cf_api_token = ?,
             resend_api_key = ?,
             bridge_token = ?,
             domains = ?,
             note = ?,
             is_primary = ?,
             status = ?,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?
         RETURNING *`,
			)
			.bind(
				account.name,
				account.cfAccountId,
				account.cfApiToken,
				account.resendApiKey,
				account.bridgeToken,
				account.domains,
				account.note,
				account.isPrimary,
				account.status,
				id,
			)
			.first();
		return mapAccount(row, { detail: true });
	},

	async delete(c, idInput) {
		const id = Number(idInput);
		const row = await assertDb(c)
			.prepare(`SELECT is_primary FROM cf_account WHERE id = ? LIMIT 1`)
			.bind(id)
			.first();
		if (!row) throw new BizError('CF account not found', 404);
		if (Number(row.is_primary || 0) === 1) throw new BizError('Primary account cannot be deleted', 400);
		await assertDb(c).prepare(`DELETE FROM cf_account WHERE id = ?`).bind(id).run();
	}
};

export default cfAccountService;
