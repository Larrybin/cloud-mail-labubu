import { describe, expect, it } from 'vitest';
import { decryptFormTenantSecret, encryptFormTenantSecret } from '../src/utils/form-tenant-crypto';

const KEYRING_RAW = JSON.stringify({
	v1: 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=',
	v2: 'ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA='
});

describe('form tenant crypto', () => {
	it('encrypt/decrypt roundtrip works with same kid', async () => {
		const plaintext = 're_test_xxx';
		const ciphertext = await encryptFormTenantSecret({
			plaintext,
			kid: 'v1',
			keyringRaw: KEYRING_RAW
		});
		const decrypted = await decryptFormTenantSecret({
			ciphertext,
			kid: 'v1',
			keyringRaw: KEYRING_RAW
		});
		expect(decrypted).toBe(plaintext);
	});

	it('decrypt fails when kid mismatches', async () => {
		const ciphertext = await encryptFormTenantSecret({
			plaintext: 're_test_xxx',
			kid: 'v1',
			keyringRaw: KEYRING_RAW
		});
		await expect(
			decryptFormTenantSecret({
				ciphertext,
				kid: 'v2',
				keyringRaw: KEYRING_RAW
			})
		).rejects.toThrow();
	});

	it('encrypt fails when kid missing in keyring', async () => {
		await expect(
			encryptFormTenantSecret({
				plaintext: 're_test_xxx',
				kid: 'missing',
				keyringRaw: KEYRING_RAW
			})
		).rejects.toThrow();
	});
});
