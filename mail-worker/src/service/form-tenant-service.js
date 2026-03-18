import BizError from '../error/biz-error';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function toText(value) {
	return typeof value === 'string' ? value.trim() : '';
}

function normalizeOrigin(value) {
	const raw = toText(value);
	if (!raw) return '';
	try {
		return new URL(raw).origin;
	} catch {
		return '';
	}
}

function normalizeStatus(value) {
	const status = toText(value).toLowerCase();
	if (!status) return 'inactive';
	return status;
}

function normalizeEmailValue(value) {
	return toText(value).toLowerCase();
}

function isValidEmail(value) {
	return EMAIL_REGEX.test(normalizeEmailValue(value));
}

function mapTenantRow(row) {
	if (!row || typeof row !== 'object') return null;
	return {
		brandId: toText(row.brand_id),
		brandName: toText(row.brand_name),
		siteOrigin: normalizeOrigin(row.site_origin),
		fromEmail: normalizeEmailValue(row.from_email),
		fromName: toText(row.from_name) || 'Form',
		toEmail: normalizeEmailValue(row.to_email),
		resendKeyCiphertext: toText(row.resend_key_ciphertext),
		resendKeyKid: toText(row.resend_key_kid),
		status: normalizeStatus(row.status)
	};
}

function assertDb(c) {
	if (!c?.env?.db || typeof c.env.db.prepare !== 'function') {
		throw new BizError('D1 is not configured', 503);
	}
	return c.env.db;
}

async function queryFirst(c, sql, bindings) {
	const db = assertDb(c);
	return await db.prepare(sql).bind(...bindings).first();
}

function assertTenantShape(tenant) {
	if (!tenant) {
		throw new BizError('Form tenant not found', 403);
	}
	if (!tenant.brandId || !tenant.siteOrigin) {
		throw new BizError('Form tenant invalid', 503);
	}
	if (!isValidEmail(tenant.fromEmail) || !isValidEmail(tenant.toEmail)) {
		throw new BizError('Form tenant email invalid', 503);
	}
	if (!tenant.resendKeyCiphertext || !tenant.resendKeyKid) {
		throw new BizError('Form tenant resend key invalid', 503);
	}
}

const formTenantService = {
	async getTenantByBrandId(c, brandIdInput) {
		const brandId = toText(brandIdInput);
		if (!brandId) return null;
		const row = await queryFirst(
			c,
			`SELECT brand_id, brand_name, site_origin, from_email, from_name, to_email, resend_key_ciphertext, resend_key_kid, status
       FROM form_tenant
       WHERE brand_id = ?
       LIMIT 1`,
			[brandId]
		);
		return mapTenantRow(row);
	},

	async getTenantByOrigin(c, originInput) {
		const origin = normalizeOrigin(originInput);
		if (!origin) return null;
		const row = await queryFirst(
			c,
			`SELECT brand_id, brand_name, site_origin, from_email, from_name, to_email, resend_key_ciphertext, resend_key_kid, status
       FROM form_tenant
       WHERE site_origin = ?
       LIMIT 1`,
			[origin]
		);
		return mapTenantRow(row);
	},

	assertTenantActive(tenant) {
		assertTenantShape(tenant);
		if (tenant.status !== 'active') {
			throw new BizError('Form tenant inactive', 403);
		}
	},

	assertSiteOriginMatch(tenant, siteOriginInput) {
		const siteOrigin = normalizeOrigin(siteOriginInput);
		if (!siteOrigin) {
			throw new BizError('siteOrigin is required', 400);
		}
		if (siteOrigin !== tenant.siteOrigin) {
			throw new BizError('Form tenant origin mismatch', 403);
		}
	},

	normalizeOrigin
};

export default formTenantService;
