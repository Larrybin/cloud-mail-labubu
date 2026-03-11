import app from '../hono/hono';
import result from '../model/result';
import formService from '../service/form-service';

app.post('/form/submit', async (c) => {
	const data = await formService.submit(c);
	return c.json(result.ok(data));
});

app.get('/form/file', async (c) => {
	return await formService.getFile(c);
});
