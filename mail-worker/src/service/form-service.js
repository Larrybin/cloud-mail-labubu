import BizError from '../error/biz-error';
import { Resend } from 'resend';

export const FORM_ATTACHMENT_PREFIX = 'form-attachments/';
const FORM_FILE_SIGN_PURPOSE = 'form-file';
const DEFAULT_FILE_TTL_SECONDS = 7 * 24 * 60 * 60;
const MAX_FORM_JSON_BYTES = 64 * 1024;
const MAX_FORM_MULTIPART_BYTES = 12 * 1024 * 1024;
const MAX_FILES = 5;
const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024;
const MAX_TOTAL_FILE_SIZE_BYTES = 10 * 1024 * 1024;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALLOWED_EXTENSIONS = new Set([
	'jpg',
	'jpeg',
	'png',
	'webp',
	'pdf',
	'doc',
	'docx',
	'xls',
	'xlsx'
]);

function toText(value) {
	return typeof value === 'string' ? value.trim() : '';
}

function escapeHtml(value) {
	return String(value || '')
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

function getFileExt(name) {
	const filename = toText(name).toLowerCase();
	const dot = filename.lastIndexOf('.');
	if (dot <= 0 || dot === filename.length - 1) return '';
	return filename.slice(dot + 1);
}

function sanitizeFilename(filename) {
	const raw = toText(filename);
	if (!raw) return 'upload';
	const cleaned = raw.replace(/[/\\?%*:|"<>]/g, '-').replace(/\s+/g, ' ').trim();
	return cleaned.slice(-120) || 'upload';
}

function isValidEmail(value) {
	return EMAIL_REGEX.test(toText(value));
}

function normalizeEmailValue(value) {
	return toText(value).toLowerCase();
}

function parseFields(rawValue) {
	if (!rawValue) return {};
	if (typeof rawValue === 'object' && !Array.isArray(rawValue)) {
		return rawValue;
	}
	if (typeof rawValue !== 'string') return {};
	const trimmed = rawValue.trim();
	if (!trimmed) return {};
	try {
		const parsed = JSON.parse(trimmed);
		if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
			return parsed;
		}
	} catch {
		// ignore invalid JSON and fallback to plain text field
	}
	return { message: trimmed };
}

function collectFilesFromFormData(formData) {
	const files = [];
	for (const [key, value] of formData.entries()) {
		if (!(value instanceof File)) continue;
		if (!value.size) continue;
		if (key === 'files' || key.startsWith('file_') || key.startsWith('files[')) {
			files.push(value);
		}
	}
	return files;
}

function resolveFileTtlSeconds(env) {
	const parsed = Number.parseInt(String(env.FORM_FILE_TTL_SECONDS || ''), 10);
	if (Number.isFinite(parsed) && parsed > 0) return parsed;
	return DEFAULT_FILE_TTL_SECONDS;
}

async function toHex(buffer) {
	return Array.from(new Uint8Array(buffer))
		.map((item) => item.toString(16).padStart(2, '0'))
		.join('');
}

export async function createFormFileSignature({ key, expMs, secret, purpose = FORM_FILE_SIGN_PURPOSE }) {
	const normalizedSecret = toText(secret);
	if (!normalizedSecret) return '';
	const payload = `${key}:${expMs}:${purpose}`;
	const data = new TextEncoder().encode(payload);
	const cryptoKey = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(normalizedSecret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign']
	);
	const signed = await crypto.subtle.sign('HMAC', cryptoKey, data);
	return await toHex(signed);
}

export async function verifyFormFileSignature({ key, expMs, sig, secret }) {
	const exp = Number.parseInt(String(expMs || ''), 10);
	if (!Number.isFinite(exp) || exp <= Date.now()) return false;
	const expectedSig = await createFormFileSignature({ key, expMs: String(exp), secret });
	if (!expectedSig) return false;
	return toText(sig) === expectedSig;
}

function validateFiles(files) {
	if (files.length > MAX_FILES) {
		throw new BizError('Too many files', 400);
	}
	const totalSize = files.reduce((sum, file) => sum + Number(file.size || 0), 0);
	if (totalSize > MAX_TOTAL_FILE_SIZE_BYTES) {
		throw new BizError('Total file size exceeds limit', 400);
	}
	for (const file of files) {
		if (Number(file.size || 0) > MAX_FILE_SIZE_BYTES) {
			throw new BizError('File too large', 400);
		}
		const ext = getFileExt(file.name);
		if (!ALLOWED_EXTENSIONS.has(ext)) {
			throw new BizError('Unsupported file type', 400);
		}
	}
}

function resolveAllowedToEmails(env) {
	return String(env.FORM_ALLOWED_TO_EMAILS || '')
		.split(',')
		.map((item) => normalizeEmailValue(item))
		.filter(Boolean);
}

function resolveBodySizeLimit(contentType) {
	if (contentType.includes('multipart/form-data')) {
		return MAX_FORM_MULTIPART_BYTES;
	}
	return MAX_FORM_JSON_BYTES;
}

function validateRequestSize(c, contentType) {
	const rawLength = toText(c.req.header('content-length'));
	if (!rawLength) {
		throw new BizError('Content-Length required', 411);
	}

	const length = Number.parseInt(rawLength, 10);
	if (!Number.isFinite(length) || length < 0) {
		throw new BizError('Invalid Content-Length', 400);
	}

	if (length > resolveBodySizeLimit(contentType)) {
		throw new BizError('Payload too large', 413);
	}
}

function validateSubmitPayload(payload, env) {
	if (!['quote', 'subscribe'].includes(payload.type)) {
		throw new BizError('Invalid form type', 400);
	}
	if (!isValidEmail(payload.toEmail)) {
		throw new BizError('Invalid toEmail', 400);
	}
	if (!isValidEmail(payload.fromEmail)) {
		throw new BizError('Invalid fromEmail', 400);
	}

	const allowedToEmails = resolveAllowedToEmails(env);
	if (!allowedToEmails.length) {
		throw new BizError('FORM_ALLOWED_TO_EMAILS is missing', 503);
	}

	if (!allowedToEmails.includes(normalizeEmailValue(payload.toEmail))) {
		throw new BizError('Forbidden toEmail', 403);
	}
}

function formatFieldsRows(fields) {
	return Object.entries(fields).map(([key, value]) => {
		const safeKey = escapeHtml(key);
		const safeValue = escapeHtml(typeof value === 'string' ? value : JSON.stringify(value));
		return `<tr><td style="padding:8px;border:1px solid #ddd;"><strong>${safeKey}</strong></td><td style="padding:8px;border:1px solid #ddd;">${safeValue}</td></tr>`;
	});
}

function buildSubmitEmailHtml({ payload, attachmentLinks }) {
	const rows = formatFieldsRows(payload.fields || {});
	if (payload.siteOrigin) {
		rows.push(
			`<tr><td style="padding:8px;border:1px solid #ddd;"><strong>siteOrigin</strong></td><td style="padding:8px;border:1px solid #ddd;">${escapeHtml(payload.siteOrigin)}</td></tr>`
		);
	}
	if (attachmentLinks.length > 0) {
		rows.push(
			`<tr><td style="padding:8px;border:1px solid #ddd;"><strong>files</strong></td><td style="padding:8px;border:1px solid #ddd;">${attachmentLinks.map((item) => `<a href="${escapeHtml(item.url)}">${escapeHtml(item.name)}</a>`).join('<br/>')}</td></tr>`
		);
	}
	return `
		<h2>${payload.type === 'quote' ? 'Quote Request' : 'Subscription Request'}</h2>
		<table style="border-collapse:collapse;width:100%;max-width:720px;">
			<tr><td style="padding:8px;border:1px solid #ddd;"><strong>fromName</strong></td><td style="padding:8px;border:1px solid #ddd;">${escapeHtml(payload.fromName)}</td></tr>
			<tr><td style="padding:8px;border:1px solid #ddd;"><strong>fromEmail</strong></td><td style="padding:8px;border:1px solid #ddd;">${escapeHtml(payload.fromEmail)}</td></tr>
			${rows.join('')}
		</table>
	`;
}

async function rollbackUploadedFiles(c, uploadedKeys) {
	if (!uploadedKeys.length) return;
	if (!c.env.r2 || typeof c.env.r2.delete !== 'function') return;
	try {
		await c.env.r2.delete(uploadedKeys);
	} catch (error) {
		console.error('Rollback uploaded files failed', error);
	}
}

async function uploadFiles(c, files) {
	if (!files.length) {
		return { uploadedKeys: [], attachmentLinks: [] };
	}

	if (!c.env.r2 || typeof c.env.r2.put !== 'function') {
		throw new BizError('R2 is not configured', 503);
	}
	const secret = toText(c.env.FORM_FILE_SECRET);
	if (!secret) {
		throw new BizError('FORM_FILE_SECRET is missing', 503);
	}

	validateFiles(files);

	const requestOrigin = new URL(c.req.url).origin;
	const fileTtlSeconds = resolveFileTtlSeconds(c.env);
	const uploadedKeys = [];
	const attachmentLinks = [];

	for (const file of files) {
		const safeName = sanitizeFilename(file.name);
		const key = `${FORM_ATTACHMENT_PREFIX}${crypto.randomUUID()}-${Date.now()}-${safeName}`;
		uploadedKeys.push(key);
		await c.env.r2.put(key, file, {
			httpMetadata: {
				contentType: toText(file.type) || 'application/octet-stream',
				contentDisposition: `attachment; filename="${safeName}"`
			},
			customMetadata: {
				uploadedBy: 'form-submit',
				originalName: safeName
			}
		});
		const expMs = String(Date.now() + fileTtlSeconds * 1000);
		const sig = await createFormFileSignature({ key, expMs, secret });
		const url = new URL('/api/form/file', requestOrigin);
		url.searchParams.set('key', key);
		url.searchParams.set('exp', expMs);
		url.searchParams.set('sig', sig);
		attachmentLinks.push({ name: safeName, url: url.toString() });
	}

	return { uploadedKeys, attachmentLinks };
}

async function parseSubmitPayload(c) {
	const contentType = toText(c.req.header('content-type')).toLowerCase();
	validateRequestSize(c, contentType);
	if (contentType.includes('multipart/form-data')) {
		const formData = await c.req.formData();
		return {
			payload: {
				type: toText(formData.get('type')) || 'quote',
				siteOrigin: toText(formData.get('siteOrigin')),
				fromEmail: toText(formData.get('fromEmail')),
				fromName: toText(formData.get('fromName')),
				toEmail: toText(formData.get('toEmail')),
				fields: parseFields(formData.get('fields'))
			},
			files: collectFilesFromFormData(formData)
		};
	}

	const body = await c.req.json();
	return {
		payload: {
			type: toText(body?.type) || 'quote',
			siteOrigin: toText(body?.siteOrigin),
			fromEmail: toText(body?.fromEmail),
			fromName: toText(body?.fromName),
			toEmail: toText(body?.toEmail),
			fields: parseFields(body?.fields)
		},
		files: []
	};
}

const formService = {
	async submit(c) {
		const resendApiKey = toText(c.env.FORM_RESEND_API_KEY);
		if (!resendApiKey) {
			throw new BizError('FORM_RESEND_API_KEY is missing', 503);
		}

		const { payload, files } = await parseSubmitPayload(c);
		validateSubmitPayload(payload, c.env);

		let uploadedKeys = [];
		let attachmentLinks = [];
		try {
			const uploadResult = await uploadFiles(c, files);
			uploadedKeys = uploadResult.uploadedKeys;
			attachmentLinks = uploadResult.attachmentLinks;

			let sendResult = null;
			if (typeof c.env.FORM_SEND_EMAIL_FN === 'function') {
				sendResult = await c.env.FORM_SEND_EMAIL_FN({
					payload,
					attachmentLinks,
					resendApiKey
				});
			} else {
				const resend = new Resend(resendApiKey);
				sendResult = await resend.emails.send({
					from: `${payload.fromName || 'Form'} <${payload.fromEmail}>`,
					to: [payload.toEmail],
					subject: payload.type === 'quote' ? 'New Quote Request' : 'New Subscription',
					html: buildSubmitEmailHtml({ payload, attachmentLinks })
				});
			}

			if (sendResult?.error) {
				throw new Error(sendResult.error.message || 'Send email failed');
			}
		} catch (error) {
			await rollbackUploadedFiles(c, uploadedKeys);
			throw error;
		}

		return {
			attachmentCount: attachmentLinks.length
		};
	},

	async getFile(c) {
		const key = toText(c.req.query('key'));
		const exp = toText(c.req.query('exp'));
		const sig = toText(c.req.query('sig'));
		if (!key.startsWith(FORM_ATTACHMENT_PREFIX)) {
			throw new BizError('Not Found', 404);
		}

		const secret = toText(c.env.FORM_FILE_SECRET);
		if (!secret) {
			throw new BizError('FORM_FILE_SECRET is missing', 503);
		}

		const verified = await verifyFormFileSignature({ key, expMs: exp, sig, secret });
		if (!verified) {
			throw new BizError('Unauthorized', 401);
		}

		if (!c.env.r2 || typeof c.env.r2.get !== 'function') {
			throw new BizError('R2 is not configured', 503);
		}
		const obj = await c.env.r2.get(key);
		if (!obj) {
			throw new BizError('Not Found', 404);
		}

		const headers = new Headers();
		obj.writeHttpMetadata(headers);
		headers.set('etag', obj.httpEtag || '');
		headers.set('cache-control', 'private, no-store');
		headers.set('x-robots-tag', 'noindex, nofollow');
		return new Response(obj.body, { status: 200, headers });
	}
};

export default formService;
