import app from '../hono/hono'
import result from '../model/result'
import BizError from '../error/biz-error'
import subscriberService from '../service/subscriber-service'

const MAX_SUBSCRIBE_JSON_BYTES = 64 * 1024

function validateSubscribeRequestSize(c) {
	const rawLength = String(c.req.header('content-length') || '').trim()
	if (!rawLength) {
		throw new BizError('Content-Length required', 411)
	}

	if (!/^\d+$/.test(rawLength)) {
		throw new BizError('Invalid Content-Length', 400)
	}
	const length = Number.parseInt(rawLength, 10)

	if (length > MAX_SUBSCRIBE_JSON_BYTES) {
		throw new BizError('Payload too large', 413)
	}
}

app.post('/subscriber/subscribe', async (c) => {
	validateSubscribeRequestSize(c)
	const payload = await c.req.json()
	const data = await subscriberService.subscribe(c, payload)
	return c.json(result.ok(data))
})

app.get('/subscriber/list', async (c) => {
	const data = await subscriberService.list(c, c.req.query())
	return c.json(result.ok(data))
})

app.get('/subscriber/export', async (c) => {
	const csv = await subscriberService.exportCsv(c, c.req.query())
	return new Response(csv, {
		headers: {
			'Content-Type': 'text/csv; charset=utf-8',
			'Content-Disposition': 'attachment; filename="subscribers.csv"'
		}
	})
})
