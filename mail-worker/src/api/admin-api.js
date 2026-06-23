import app from '../hono/hono';
import result from '../model/result';
import cfAccountService from '../service/cf-account-service';
import adminSummaryService from '../service/admin-summary-service';

app.get('/admin/cf-accounts', async (c) => {
	const data = await cfAccountService.list(c, c.req.query());
	return c.json(result.ok(data));
});

app.get('/admin/cf-accounts/:id', async (c) => {
	const data = await cfAccountService.detail(c, c.req.param('id'));
	return c.json(result.ok(data));
});

app.post('/admin/cf-accounts', async (c) => {
	const data = await cfAccountService.create(c, await c.req.json());
	return c.json(result.ok(data));
});

app.put('/admin/cf-accounts/:id', async (c) => {
	const data = await cfAccountService.update(c, c.req.param('id'), await c.req.json());
	return c.json(result.ok(data));
});

app.delete('/admin/cf-accounts/:id', async (c) => {
	await cfAccountService.delete(c, c.req.param('id'));
	return c.json(result.ok());
});

app.get('/admin/cloud-mail/summary', async (c) => {
	const data = await adminSummaryService.get(c);
	return c.json(result.ok(data));
});
