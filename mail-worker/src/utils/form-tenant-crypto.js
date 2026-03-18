const AES_ALGORITHM = 'AES-GCM';
const AES_KEY_LENGTH_BYTES = 32;
const AES_IV_LENGTH_BYTES = 12;

function toText(value) {
	return typeof value === 'string' ? value.trim() : '';
}

function isPlainObject(value) {
	return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function base64ToBytes(value) {
	try {
		const binary = atob(value);
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i += 1) {
			bytes[i] = binary.charCodeAt(i);
		}
		return bytes;
	} catch {
		return null;
	}
}

function bytesToBase64(bytes) {
	let binary = '';
	for (let i = 0; i < bytes.length; i += 1) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary);
}

function parseKeyring(rawValue) {
	const text = toText(rawValue);
	if (!text) return new Map();

	let parsed = null;
	try {
		parsed = JSON.parse(text);
	} catch {
		return new Map();
	}
	if (!isPlainObject(parsed)) return new Map();

	const keyring = new Map();
	for (const [rawKid, rawKey] of Object.entries(parsed)) {
		const kid = toText(rawKid);
		const keyBase64 = toText(rawKey);
		if (!kid || !keyBase64) continue;
		const keyBytes = base64ToBytes(keyBase64);
		if (!keyBytes) continue;
		if (keyBytes.byteLength !== AES_KEY_LENGTH_BYTES) continue;
		keyring.set(kid, keyBytes);
	}
	return keyring;
}

async function importAesKey(keyBytes) {
	return await crypto.subtle.importKey('raw', keyBytes, { name: AES_ALGORITHM }, false, [
		'encrypt',
		'decrypt'
	]);
}

function parseCiphertext(value) {
	const text = toText(value);
	if (!text) return null;
	const dotIndex = text.indexOf('.');
	if (dotIndex <= 0 || dotIndex >= text.length - 1) return null;
	const ivPart = text.slice(0, dotIndex);
	const encryptedPart = text.slice(dotIndex + 1);
	const iv = base64ToBytes(ivPart);
	const encrypted = base64ToBytes(encryptedPart);
	if (!iv || !encrypted) return null;
	if (iv.byteLength !== AES_IV_LENGTH_BYTES) return null;
	if (encrypted.byteLength === 0) return null;
	return { iv, encrypted };
}

function buildCiphertext({ iv, encrypted }) {
	return `${bytesToBase64(iv)}.${bytesToBase64(encrypted)}`;
}

function resolveKeyBytes({ keyringRaw, kid }) {
	const normalizedKid = toText(kid);
	if (!normalizedKid) {
		throw new Error('tenant key kid is required');
	}
	const keyring = parseKeyring(keyringRaw);
	const keyBytes = keyring.get(normalizedKid);
	if (!keyBytes) {
		throw new Error(`tenant key not found for kid: ${normalizedKid}`);
	}
	return keyBytes;
}

export async function encryptFormTenantSecret({ plaintext, keyringRaw, kid }) {
	const normalizedPlaintext = toText(plaintext);
	if (!normalizedPlaintext) {
		throw new Error('tenant secret plaintext is required');
	}
	const keyBytes = resolveKeyBytes({ keyringRaw, kid });
	const cryptoKey = await importAesKey(keyBytes);
	const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH_BYTES));
	const encoded = new TextEncoder().encode(normalizedPlaintext);
	const encryptedBuffer = await crypto.subtle.encrypt(
		{
			name: AES_ALGORITHM,
			iv
		},
		cryptoKey,
		encoded
	);
	return buildCiphertext({ iv, encrypted: new Uint8Array(encryptedBuffer) });
}

export async function decryptFormTenantSecret({ ciphertext, keyringRaw, kid }) {
	const parsed = parseCiphertext(ciphertext);
	if (!parsed) {
		throw new Error('tenant secret ciphertext invalid');
	}
	const keyBytes = resolveKeyBytes({ keyringRaw, kid });
	const cryptoKey = await importAesKey(keyBytes);
	const decryptedBuffer = await crypto.subtle.decrypt(
		{
			name: AES_ALGORITHM,
			iv: parsed.iv
		},
		cryptoKey,
		parsed.encrypted
	);
	return new TextDecoder().decode(decryptedBuffer).trim();
}
