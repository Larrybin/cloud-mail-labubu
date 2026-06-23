import BizError from '../error/biz-error';

const STATUSES = new Set(['unread', 'read', 'replied']);

function toText(value) {
	return typeof value === 'string' ? value.trim() : '';
}

function parsePositiveInt(value, fallback) {
	const parsed = Number.parseInt(String(value || ''), 10);
	return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function pickField(fields, names) {
	for (const name of names) {
		const direct = fields?.[name];
		if (toText(direct)) return toText(direct);
		const match = Object.keys(fields || {}).find(key => key.toLowerCase() === name.toLowerCase());
		if (match && toText(fields[match])) return toText(fields[match]);
	}
	return '';
}

function mapInquiry(row) {
	let attachments = [];
	try {
		attachments = JSON.parse(row.attachments_json || '[]');
	} catch {
		attachments = [];
	}
	return {
		id: Number(row.id),
		brandId: toText(row.brand_id),
		siteOrigin: toText(row.site_origin),
		name: toText(row.name),
		email: toText(row.email),
		company: toText(row.company),
		message: toText(row.message),
		html: toText(row.html),
		attachments,
		status: toText(row.status) || 'unread',
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

function buildWhere(params) {
	const conditions = [];
	const bindings = [];
	const keyword = toText(params.keyword);
	const brandId = toText(params.brandId);
	const status = toText(params.status);

	if (brandId) {
		conditions.push('brand_id = ?');
		bindings.push(brandId);
	}
	if (status) {
		conditions.push('status = ?');
		bindings.push(status);
	}
	if (keyword) {
		conditions.push('(name LIKE ? OR email LIKE ? OR company LIKE ? OR message LIKE ? OR brand_id LIKE ?)');
		const like = `%${keyword}%`;
		bindings.push(like, like, like, like, like);
	}

	return {
		sql: conditions.length ? `WHERE ${conditions.join(' AND ')}` : '',
		bindings
	};
}

const formInquiryService = {
	async create(c, { payload, fields, html, attachments }) {
		const name = pickField(fields, ['name', 'fullName', 'contactName']) || payload.fromName || 'Sender';
		const email = pickField(fields, ['email', 'contactEmail', 'fromEmail']) || payload.fromEmail;
		const company = pickField(fields, ['company', 'companyName', 'organization']);
		const message = pickField(fields, ['message', 'content', 'note', 'comments']) || JSON.stringify(fields || {});
		const row = await assertDb(c)
			.prepare(
				`INSERT INTO form_inquiry (
          brand_id, site_origin, name, email, company, message, html, attachments_json, status, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unread', CURRENT_TIMESTAMP)
        RETURNING *`,
			)
			.bind(
				payload.brandId,
				payload.siteOrigin,
				name,
				email,
				company,
				message,
				html,
				JSON.stringify(attachments || []),
			)
			.first();
		return mapInquiry(row);
	},

	async list(c, params = {}) {
		const page = parsePositiveInt(params.page, 1);
		const size = Math.min(parsePositiveInt(params.size, 50), 100);
		const offset = (page - 1) * size;
		const where = buildWhere(params);
		const db = assertDb(c);
		const [listResult, totalRow] = await Promise.all([
			db
				.prepare(
					`SELECT *
           FROM form_inquiry
           ${where.sql}
           ORDER BY created_at DESC, id DESC
           LIMIT ? OFFSET ?`,
				)
				.bind(...where.bindings, size, offset)
				.all(),
			db
				.prepare(`SELECT COUNT(*) AS total FROM form_inquiry ${where.sql}`)
				.bind(...where.bindings)
				.first()
		]);
		const rows = Array.isArray(listResult?.results) ? listResult.results : [];
		return {
			list: rows.map(mapInquiry),
			total: Number(totalRow?.total || 0),
			page,
			size
		};
	},

	async setStatus(c, idInput, payload) {
		const id = Number(idInput);
		const status = toText(payload?.status);
		if (!STATUSES.has(status)) throw new BizError('Invalid inquiry status', 400);
		const row = await assertDb(c)
			.prepare(
				`UPDATE form_inquiry
         SET status = ?, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?
         RETURNING *`,
			)
			.bind(status, id)
			.first();
		if (!row) throw new BizError('Inquiry not found', 404);
		return mapInquiry(row);
	}
};

export default formInquiryService;
