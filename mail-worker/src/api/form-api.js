import app from '../hono/hono';
import result from '../model/result';
import formService from '../service/form-service';
import formInquiryService from '../service/form-inquiry-service';

app.post('/form/submit', async (c) => {
	const data = await formService.submit(c);
	return c.json(result.ok(data));
});

app.get('/form/file', async (c) => {
	return await formService.getFile(c);
});

app.get('/form/inquiries', async (c) => {
	const data = await formInquiryService.list(c, c.req.query());
	return c.json(result.ok(data));
});

app.patch('/form/inquiries/:id/status', async (c) => {
	const data = await formInquiryService.setStatus(c, c.req.param('id'), await c.req.json());
	return c.json(result.ok(data));
});
