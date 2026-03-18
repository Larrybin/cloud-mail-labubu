import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: './wrangler-test.toml' },
		}),
	],
	test: {
		poolMatchGlobs: [['test/form-tenant-cli.spec.js', 'threads']],
	},
});
