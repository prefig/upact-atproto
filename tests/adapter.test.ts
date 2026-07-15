import { describe, it, expect, vi } from 'vitest';
import { createAtprotoAdapter, deriveMemberId, buildClientMetadata } from '../src/index.js';
import type { AtprotoConfig, AtprotoOAuthClient, Session } from '../src/index.js';

const DID = 'did:plc:abcdefghijklmnopqrstuvwx';
const CONFIG: AtprotoConfig = { baseUrl: 'https://rp.example', clientName: 'dyad' };

/** A callback-params double for authenticate(). */
function callbackCredential(overrides: Record<string, string> = {}) {
	const params = new URLSearchParams({ code: 'auth-code', state: 'alice.bsky.social', ...overrides });
	return { kind: 'atproto-callback' as const, params };
}

/** An injectable OAuth client double. */
function fakeClient(opts: {
	did?: string;
	callbackThrows?: unknown;
	onSignOut?: () => void;
	authorizeUrl?: string;
} = {}): AtprotoOAuthClient {
	return {
		async authorize(input, options) {
			const url = new URL(opts.authorizeUrl ?? 'https://pds.example/oauth/authorize');
			url.searchParams.set('login_hint', input);
			url.searchParams.set('state', options.state);
			url.searchParams.set('scope', options.scope);
			return url;
		},
		async callback() {
			if (opts.callbackThrows !== undefined) throw opts.callbackThrows;
			return {
				session: {
					did: opts.did ?? DID,
					async signOut() {
						opts.onSignOut?.();
					},
				},
				state: 'alice.bsky.social',
			};
		},
	};
}

describe('authenticate — terminal callback exchange', () => {
	it('resolves a callback with a code to an opaque Session carrying the mapped Upactor', async () => {
		const adapter = createAtprotoAdapter(CONFIG, fakeClient());
		const outcome = await adapter.authenticate(callbackCredential());
		expect(isAuthError(outcome)).toBe(false);
		const upactor = adapter.upactorForSession(outcome as Session);
		expect(upactor?.id).toBe(deriveMemberId(DID));
		expect(upactor?.provenance).toEqual({ substrate: 'atproto', instance: 'did:plc' });
		expect(upactor?.lifecycle).toEqual({ renewable: 'reauth' });
	});

	it('revokes the OAuth session (best-effort signOut) after reading the DID', async () => {
		const onSignOut = vi.fn();
		const adapter = createAtprotoAdapter(CONFIG, fakeClient({ onSignOut }));
		await adapter.authenticate(callbackCredential());
		expect(onSignOut).toHaveBeenCalledOnce();
	});

	it('still resolves when the best-effort signOut rejects', async () => {
		const client = fakeClient();
		client.callback = async () => ({
			session: { did: DID, signOut: async () => { throw new Error('revocation failed'); } },
			state: null,
		});
		const adapter = createAtprotoAdapter(CONFIG, client);
		const outcome = await adapter.authenticate(callbackCredential());
		expect(isAuthError(outcome)).toBe(false);
		expect(adapter.upactorForSession(outcome as Session)?.id).toBe(deriveMemberId(DID));
	});

	it('rejects an unrecognised credential shape as credential_invalid', async () => {
		const adapter = createAtprotoAdapter(CONFIG, fakeClient());
		expect(await adapter.authenticate({ nope: true })).toMatchObject({ code: 'credential_invalid' });
		expect(await adapter.authenticate(null)).toMatchObject({ code: 'credential_invalid' });
	});

	it('rejects a callback missing its code as credential_invalid, before any client call', async () => {
		const callback = vi.fn();
		const client = fakeClient();
		client.callback = callback as never;
		const adapter = createAtprotoAdapter(CONFIG, client);
		const params = new URLSearchParams({ state: 'alice.bsky.social' });
		const outcome = await adapter.authenticate({ kind: 'atproto-callback', params });
		expect(outcome).toMatchObject({ code: 'credential_invalid' });
		expect(callback).not.toHaveBeenCalled();
	});

	it('maps a rejected/failed callback exchange to credential_rejected', async () => {
		const adapter = createAtprotoAdapter(
			CONFIG,
			fakeClient({ callbackThrows: new Error('invalid_grant: code already used') }),
		);
		expect(await adapter.authenticate(callbackCredential())).toMatchObject({
			code: 'credential_rejected',
		});
	});

	it('maps a transport failure to substrate_unavailable', async () => {
		const adapter = createAtprotoAdapter(
			CONFIG,
			fakeClient({ callbackThrows: new TypeError('fetch failed') }),
		);
		expect(await adapter.authenticate(callbackCredential())).toMatchObject({
			code: 'substrate_unavailable',
		});
	});

	it('maps a rate-limit to rate_limited', async () => {
		const adapter = createAtprotoAdapter(
			CONFIG,
			fakeClient({ callbackThrows: new Error('Unexpected 429 Too Many Requests') }),
		);
		expect(await adapter.authenticate(callbackCredential())).toMatchObject({
			code: 'rate_limited',
		});
	});
});

describe('beginAuthorization — out-of-port start step', () => {
	it('returns the authorization URL from the client, carrying the handle as state', async () => {
		const adapter = createAtprotoAdapter(CONFIG, fakeClient());
		const url = await adapter.beginAuthorization('alice.bsky.social');
		expect(url).toBeInstanceOf(URL);
		expect(url.searchParams.get('state')).toBe('alice.bsky.social');
		expect(url.searchParams.get('scope')).toBe('atproto');
	});
});

describe('upactorForSession', () => {
	it('returns null for a session this adapter did not produce', async () => {
		const adapter = createAtprotoAdapter(CONFIG, fakeClient());
		const foreign = { _opaque: Symbol('x') } as unknown as Session;
		expect(adapter.upactorForSession(foreign)).toBeNull();
	});
});

describe('honest-null port methods', () => {
	const adapter = createAtprotoAdapter(CONFIG, fakeClient());

	it('currentUpactor is always null (the app owns its own session)', async () => {
		expect(await adapter.currentUpactor(new Request('https://rp.example/'))).toBeNull();
	});

	it('invalidate is a no-op (the OAuth session was already revoked)', async () => {
		const outcome = await adapter.authenticate(callbackCredential());
		await expect(adapter.invalidate(outcome as Session)).resolves.toBeUndefined();
	});

	it('issueRenewal is always null (renewal is a fresh sign-in)', async () => {
		const upactor = { id: 'x', capabilities: new Set() } as never;
		expect(await adapter.issueRenewal(upactor, null)).toBeNull();
	});
});

describe('client metadata', () => {
	it('builds a web public client for an https base URL', () => {
		const meta = buildClientMetadata(CONFIG);
		expect(meta.client_id).toBe('https://rp.example/oauth/client-metadata.json');
		expect(meta.redirect_uris).toEqual(['https://rp.example/api/atproto/callback']);
		expect(meta.application_type).toBe('web');
		expect(meta.token_endpoint_auth_method).toBe('none');
		expect(meta.dpop_bound_access_tokens).toBe(true);
	});

	it('builds a loopback native client for a 127.0.0.1 base URL (dev)', () => {
		const meta = buildClientMetadata({ baseUrl: 'http://127.0.0.1:5173' });
		expect(meta.client_id).toContain('http://localhost?redirect_uri=');
		expect(meta.client_id).toContain(encodeURIComponent('http://127.0.0.1:5173/api/atproto/callback'));
		expect(meta.application_type).toBe('native');
	});
});

function isAuthError(value: unknown): boolean {
	return typeof (value as { code?: unknown }).code === 'string';
}
