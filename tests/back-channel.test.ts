import { describe, it, expect } from 'vitest';
import { inspect } from 'node:util';
import { createAtprotoAdapter } from '../src/index.js';
import type { AtprotoConfig, AtprotoOAuthClient, Session } from '../src/index.js';

/**
 * SPEC §7.5 — 16-vector closure-conformance test, parity with the sibling
 * adapters' back-channel suites. The resolved DID and the OAuth client's
 * internals MUST be unreachable through the adapter instance via any common
 * reflection path. The DID lives only inside the opaque Session
 * (createSession's process-local WeakMap); the client lives only in closure.
 */

const SENTINEL_DID = 'did:plc:SENTINELdidVALUEmustNOTleak';
const SENTINEL_CLIENT_SECRET = 'SENTINEL_OAUTH_CLIENT_INTERNAL_MATERIAL';
const CONFIG: AtprotoConfig = { baseUrl: 'https://rp.example', clientName: 'dyad' };

function sentinelClient(): AtprotoOAuthClient {
	const client = {
		// A property standing in for the client's internal token/DPoP material.
		_secret: SENTINEL_CLIENT_SECRET,
		async authorize() {
			return new URL('https://pds.example/oauth/authorize');
		},
		async callback() {
			return {
				session: { did: SENTINEL_DID, async signOut() {} },
				state: null,
			};
		},
	};
	return client as unknown as AtprotoOAuthClient;
}

async function makeAuthenticatedAdapter() {
	const adapter = createAtprotoAdapter(CONFIG, sentinelClient());
	const params = new URLSearchParams({ code: 'auth-code', state: 'alice.bsky.social' });
	const outcome = await adapter.authenticate({ kind: 'atproto-callback', params });
	return { adapter, session: outcome as Session, sentinels: [SENTINEL_DID, SENTINEL_CLIENT_SECRET] };
}

describe('createAtprotoAdapter — back-channel closure conformance (16 vectors)', () => {
	it('JSON.stringify does not leak sentinels', async () => {
		const { adapter, sentinels } = await makeAuthenticatedAdapter();
		const json = JSON.stringify(adapter);
		for (const s of sentinels) expect(json ?? '').not.toContain(s);
	});

	it('Object.keys does not surface substrate state', async () => {
		const { adapter, sentinels } = await makeAuthenticatedAdapter();
		const keys = JSON.stringify(Object.keys(adapter));
		for (const s of sentinels) expect(keys).not.toContain(s);
	});

	it('Object.getOwnPropertyNames does not surface substrate state', async () => {
		const { adapter, sentinels } = await makeAuthenticatedAdapter();
		const names = JSON.stringify(Object.getOwnPropertyNames(adapter));
		for (const s of sentinels) expect(names).not.toContain(s);
	});

	it('Reflect.ownKeys does not surface substrate state', async () => {
		const { adapter, sentinels } = await makeAuthenticatedAdapter();
		const keys = JSON.stringify(Reflect.ownKeys(adapter).map(String));
		for (const s of sentinels) expect(keys).not.toContain(s);
	});

	it('Object.getOwnPropertySymbols does not surface substrate state', async () => {
		const { adapter, sentinels } = await makeAuthenticatedAdapter();
		const syms = JSON.stringify(Object.getOwnPropertySymbols(adapter).map(String));
		for (const s of sentinels) expect(syms).not.toContain(s);
	});

	it('for-in loop does not surface substrate state', async () => {
		const { adapter, sentinels } = await makeAuthenticatedAdapter();
		const found: string[] = [];
		for (const key in adapter) found.push(key);
		const result = JSON.stringify(found);
		for (const s of sentinels) expect(result).not.toContain(s);
	});

	it('structuredClone throws (functions are not clonable — no data leak possible)', async () => {
		const { adapter } = await makeAuthenticatedAdapter();
		expect(() => structuredClone(adapter)).toThrow();
	});

	it('util.inspect does not surface sentinels', async () => {
		const { adapter, sentinels } = await makeAuthenticatedAdapter();
		const inspected = inspect(adapter, { depth: 5 });
		for (const s of sentinels) expect(inspected).not.toContain(s);
	});

	it('(adapter as any).config is undefined', async () => {
		const { adapter } = await makeAuthenticatedAdapter();
		expect((adapter as Record<string, unknown>).config).toBeUndefined();
	});

	it('(adapter as any).client is undefined (the SPEC §7.5-named property)', async () => {
		const { adapter } = await makeAuthenticatedAdapter();
		expect((adapter as Record<string, unknown>).client).toBeUndefined();
	});

	it('(adapter as any).did is undefined', async () => {
		const { adapter } = await makeAuthenticatedAdapter();
		expect((adapter as Record<string, unknown>).did).toBeUndefined();
	});

	it('(adapter as any)._client is undefined', async () => {
		const { adapter } = await makeAuthenticatedAdapter();
		expect((adapter as Record<string, unknown>)._client).toBeUndefined();
	});

	it('Object spread does not surface substrate state', async () => {
		const { adapter, sentinels } = await makeAuthenticatedAdapter();
		const spread = JSON.stringify({ ...adapter });
		for (const s of sentinels) expect(spread).not.toContain(s);
	});

	it('wrapped JSON.stringify with replacer does not surface substrate state', async () => {
		const { adapter, sentinels } = await makeAuthenticatedAdapter();
		const json = JSON.stringify(adapter, (_, v) => (typeof v === 'function' ? '[fn]' : v));
		for (const s of sentinels) expect(json ?? '').not.toContain(s);
	});

	it('Object.entries does not surface substrate state', async () => {
		const { adapter, sentinels } = await makeAuthenticatedAdapter();
		const entries = JSON.stringify(Object.entries(adapter));
		for (const s of sentinels) expect(entries).not.toContain(s);
	});

	it('the opaque Session does not surface the DID via reflection', async () => {
		const { session, sentinels } = await makeAuthenticatedAdapter();
		const surfaces = [
			JSON.stringify(session) ?? '',
			JSON.stringify(Object.keys(session)),
			JSON.stringify(Reflect.ownKeys(session).map(String)),
			inspect(session, { depth: 5 }),
			JSON.stringify({ ...session }),
		];
		for (const surface of surfaces) {
			for (const s of sentinels) expect(surface).not.toContain(s);
		}
	});
});
