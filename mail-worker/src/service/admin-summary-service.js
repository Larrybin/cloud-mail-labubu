async function countTable(c, table) {
	if (!c?.env?.db || typeof c.env.db.prepare !== 'function') return 0;
	try {
		const row = await c.env.db.prepare(`SELECT COUNT(*) AS total FROM ${table}`).first();
		return Number(row?.total || 0);
	} catch {
		return 0;
	}
}

async function recentInquiries(c) {
	if (!c?.env?.db || typeof c.env.db.prepare !== 'function') return [];
	try {
		const result = await c.env.db
			.prepare(
				`SELECT id, brand_id, name, email, status, created_at
         FROM form_inquiry
         ORDER BY created_at DESC, id DESC
         LIMIT 5`,
			)
			.all();
		const rows = Array.isArray(result?.results) ? result.results : [];
		return rows.map(row => ({
			id: Number(row.id),
			brandId: String(row.brand_id || ''),
			name: String(row.name || ''),
			email: String(row.email || ''),
			status: String(row.status || 'unread'),
			createdAt: String(row.created_at || '')
		}));
	} catch {
		return [];
	}
}

const adminSummaryService = {
	async get(c) {
		const [inquiryTotal, subscriberTotal, tenantTotal, cfAccountTotal, recent] = await Promise.all([
			countTable(c, 'form_inquiry'),
			countTable(c, 'subscriber'),
			countTable(c, 'form_tenant'),
			countTable(c, 'cf_account'),
			recentInquiries(c)
		]);

		return {
			connected: true,
			d1Configured: Boolean(c?.env?.db),
			r2Configured: Boolean(c?.env?.r2),
			inquiryTotal,
			subscriberTotal,
			tenantTotal,
			cfAccountTotal,
			recentInquiries: recent
		};
	}
};

export default adminSummaryService;
