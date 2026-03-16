import BizError from '../error/biz-error'

const DEFAULT_PAGE = 1
const DEFAULT_SIZE = 20
const MAX_SIZE = 100
const EXPORT_DEFAULT_SIZE = 5000
const MAX_EXPORT_SIZE = 5000
const MAX_SOURCE_PATH_LENGTH = 512
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const DANGEROUS_CSV_PREFIX_RE = /^[ \t]*[=+\-@]/

function toText(value) {
	return typeof value === 'string' ? value.trim() : ''
}

function normalizeMetadataText(value) {
	return toText(value).replace(/[\r\n\0]+/g, '')
}

function normalizeEmail(value) {
	return toText(value).toLowerCase()
}

function isValidEmail(value) {
	return EMAIL_REGEX.test(normalizeEmail(value))
}

function parsePositiveInt(value, fallback) {
	const parsed = Number.parseInt(String(value || ''), 10)
	return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

function normalizeSourcePath(value) {
	const normalized = normalizeMetadataText(value)
	if (!normalized) return '/'

	const withLeadingSlash = normalized.startsWith('/') ? normalized : `/${normalized}`
	return withLeadingSlash.slice(0, MAX_SOURCE_PATH_LENGTH) || '/'
}

function normalizeSiteOrigin(value) {
	const normalized = normalizeMetadataText(value)
	if (!normalized) return ''

	try {
		const url = new URL(normalized)
		if (!['http:', 'https:'].includes(url.protocol)) return ''
		return url.origin
	} catch {
		return ''
	}
}

function normalizeCsvCell(value) {
	const text = String(value ?? '')
	return DANGEROUS_CSV_PREFIX_RE.test(text) ? `'${text}` : text
}

function buildWhereClause(filters) {
	const conditions = []
	const bindings = []

	if (filters.listKey) {
		conditions.push('list_key = ?')
		bindings.push(filters.listKey)
	}

	if (filters.status) {
		conditions.push('status = ?')
		bindings.push(filters.status)
	}

	if (filters.keyword) {
		conditions.push('(email LIKE ? OR normalized_email LIKE ? OR brand_name LIKE ?)')
		const keyword = `%${filters.keyword}%`
		bindings.push(keyword, keyword, keyword)
	}

	return {
		sql: conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '',
		bindings,
	}
}

function escapeCsvValue(value) {
	const text = normalizeCsvCell(value)
	if (!/[",\n]/.test(text)) return text
	return `"${text.replace(/"/g, '""')}"`
}

function toCsv(rows) {
	const headers = [
		'email',
		'listKey',
		'brandId',
		'brandName',
		'status',
		'locale',
		'sourceType',
		'sourcePath',
		'siteOrigin',
		'firstSubscribedAt',
		'lastSubscribedAt'
	]
	const lines = [headers.join(',')]
	for (const row of rows) {
		lines.push(
			[
				row.email,
				row.listKey,
				row.brandId,
				row.brandName,
				row.status,
				row.locale,
				row.sourceType,
				row.sourcePath,
				row.siteOrigin,
				row.firstSubscribedAt,
				row.lastSubscribedAt
			]
				.map(escapeCsvValue)
				.join(',')
		)
	}
	return `${lines.join('\n')}\n`
}

function mapSubscriberRow(row) {
	return {
		subscriberId: row.subscriber_id,
		email: row.email,
		listKey: row.list_key,
		brandId: row.brand_id,
		brandName: row.brand_name,
		status: row.status,
		locale: row.locale,
		sourceType: row.source_type,
		sourcePath: row.source_path,
		siteOrigin: row.site_origin,
		firstSubscribedAt: row.first_subscribed_at,
		lastSubscribedAt: row.last_subscribed_at,
		createdAt: row.created_at,
		updatedAt: row.updated_at
	}
}

const subscriberService = {
	async subscribe(c, payload) {
		const listKey = toText(payload?.listKey)
		const email = normalizeEmail(payload?.email)
		const brandId = normalizeMetadataText(payload?.brandId) || listKey
		const brandName = normalizeMetadataText(payload?.brandName)
		const siteOrigin = normalizeSiteOrigin(payload?.siteOrigin)
		const locale = normalizeMetadataText(payload?.locale)
		const sourcePath = normalizeSourcePath(payload?.sourcePath)
		const sourceType = normalizeMetadataText(payload?.sourceType) || 'website_subscribe_form'

		if (!listKey) {
			throw new BizError('listKey is required', 400)
		}
		if (!isValidEmail(email)) {
			throw new BizError('Invalid email', 400)
		}

		const subscriberId = crypto.randomUUID()
		await c.env.db
			.prepare(
				`INSERT INTO subscriber (
          subscriber_id,
          list_key,
          email,
          normalized_email,
          status,
          source_type,
          site_origin,
          brand_id,
          brand_name,
          locale,
          source_path,
          first_subscribed_at,
          last_subscribed_at
        ) VALUES (?, ?, ?, ?, 'subscribed', ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT(list_key, normalized_email) DO UPDATE SET
          email = excluded.email,
          status = 'subscribed',
          source_type = excluded.source_type,
          site_origin = excluded.site_origin,
          brand_id = excluded.brand_id,
          brand_name = excluded.brand_name,
          locale = excluded.locale,
          source_path = excluded.source_path,
          last_subscribed_at = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP`,
			)
			.bind(
				subscriberId,
				listKey,
				email,
				email,
				sourceType,
				siteOrigin,
				brandId,
				brandName,
				locale,
				sourcePath,
			)
			.run()

		const subscriber = await c.env.db
			.prepare(
				`SELECT *
         FROM subscriber
         WHERE list_key = ? AND normalized_email = ?
         LIMIT 1`,
			)
			.bind(listKey, email)
			.first()

		if (!subscriber?.subscriber_id) {
			throw new BizError('Subscriber save failed', 500)
		}

		await c.env.db
			.prepare(
				`INSERT INTO subscriber_event (
          event_id,
          subscriber_id,
          event_type,
          payload_json
        ) VALUES (?, ?, 'subscribe', ?)`,
			)
			.bind(
				crypto.randomUUID(),
				subscriber.subscriber_id,
				JSON.stringify({
					listKey,
					email,
					brandId,
					brandName,
					siteOrigin,
					locale,
					sourcePath,
					sourceType
				}),
			)
			.run()

		return {
			subscriberId: subscriber.subscriber_id,
			status: 'subscribed',
			email,
			listKey
		}
	},

	async list(c, params) {
		const page = parsePositiveInt(params?.page, DEFAULT_PAGE)
		const size = Math.min(parsePositiveInt(params?.size, DEFAULT_SIZE), MAX_SIZE)
		const filters = {
			keyword: toText(params?.keyword),
			listKey: toText(params?.listKey),
			status: toText(params?.status)
		}
		const where = buildWhereClause(filters)
		const offset = (page - 1) * size

		const listQuery = c.env.db
			.prepare(
				`SELECT *
         FROM subscriber
         ${where.sql}
         ORDER BY last_subscribed_at DESC, updated_at DESC
         LIMIT ? OFFSET ?`,
			)
			.bind(...where.bindings, size, offset)
		const totalQuery = c.env.db
			.prepare(`SELECT COUNT(*) AS total FROM subscriber ${where.sql}`)
			.bind(...where.bindings)

		const [listResult, totalRow] = await Promise.all([listQuery.all(), totalQuery.first()])
		const rows = Array.isArray(listResult?.results) ? listResult.results : []

		return {
			list: rows.map(mapSubscriberRow),
			total: Number(totalRow?.total || 0),
			page,
			size
		}
	},

	async exportCsv(c, params) {
		const page = parsePositiveInt(params?.page, DEFAULT_PAGE)
		const size = parsePositiveInt(params?.size, EXPORT_DEFAULT_SIZE)
		if (size > MAX_EXPORT_SIZE) {
			throw new BizError(`Export size exceeds limit: ${MAX_EXPORT_SIZE}`, 400)
		}

		const filters = {
			keyword: toText(params?.keyword),
			listKey: toText(params?.listKey),
			status: toText(params?.status)
		}
		const where = buildWhereClause(filters)
		const offset = (page - 1) * size
		const result = await c.env.db
			.prepare(
				`SELECT *
         FROM subscriber
         ${where.sql}
         ORDER BY last_subscribed_at DESC, updated_at DESC
         LIMIT ? OFFSET ?`,
			)
			.bind(...where.bindings, size, offset)
			.all()
		const rows = Array.isArray(result?.results) ? result.results.map(mapSubscriberRow) : []
		return toCsv(rows)
	}
}

export default subscriberService
