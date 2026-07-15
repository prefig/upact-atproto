import { describe, it, expect, vi, afterEach } from 'vitest';
import { resolveHandleToDid } from '../src/index.js';

const DID = 'did:plc:abcdefghijklmnopqrstuvwx';

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

function stubFetch(impl: (url: string) => Promise<Response> | Response): void {
	vi.stubGlobal('fetch', vi.fn((input: unknown) => {
		const url = typeof input === 'string' ? input : String(input);
		return Promise.resolve(impl(url));
	}));
}

describe('resolveHandleToDid', () => {
	it('resolves via .well-known first (authoritative for custom-domain handles)', async () => {
		stubFetch((url) => {
			if (url.includes('/.well-known/atproto-did')) {
				return new Response(`${DID}\n`, { status: 200 });
			}
			throw new Error('AppView should not be consulted when well-known succeeds');
		});
		expect(await resolveHandleToDid('alice.example.com')).toBe(DID);
	});

	it('falls back to the AppView when well-known does not return a did', async () => {
		stubFetch((url) => {
			if (url.includes('/.well-known/atproto-did')) {
				return new Response('not found', { status: 404 });
			}
			if (url.includes('resolveHandle')) {
				return new Response(JSON.stringify({ did: DID }), { status: 200 });
			}
			return new Response('', { status: 500 });
		});
		expect(await resolveHandleToDid('alice.bsky.social')).toBe(DID);
	});

	it('falls back to the AppView when the well-known fetch throws (e.g. no such host)', async () => {
		stubFetch((url) => {
			if (url.includes('/.well-known/atproto-did')) {
				throw new TypeError('fetch failed');
			}
			if (url.includes('resolveHandle')) {
				return new Response(JSON.stringify({ did: DID }), { status: 200 });
			}
			return new Response('', { status: 500 });
		});
		expect(await resolveHandleToDid('alice.bsky.social')).toBe(DID);
	});

	it('ignores a well-known body that is not a did and uses the AppView', async () => {
		stubFetch((url) => {
			if (url.includes('/.well-known/atproto-did')) {
				return new Response('this is not a did', { status: 200 });
			}
			if (url.includes('resolveHandle')) {
				return new Response(JSON.stringify({ did: DID }), { status: 200 });
			}
			return new Response('', { status: 500 });
		});
		expect(await resolveHandleToDid('alice.bsky.social')).toBe(DID);
	});

	it('returns null when neither path resolves', async () => {
		stubFetch(() => new Response('nope', { status: 404 }));
		expect(await resolveHandleToDid('nobody.invalid')).toBeNull();
	});

	it('returns null when the AppView returns 200 with no did field', async () => {
		stubFetch((url) => {
			if (url.includes('resolveHandle')) {
				return new Response(JSON.stringify({ notDid: 'x' }), { status: 200 });
			}
			return new Response('', { status: 404 });
		});
		expect(await resolveHandleToDid('weird.example')).toBeNull();
	});

	it('url-encodes the handle in the AppView query', async () => {
		const seen: string[] = [];
		stubFetch((url) => {
			seen.push(url);
			return new Response('', { status: 404 });
		});
		await resolveHandleToDid('a b/c');
		const appviewCall = seen.find((u) => u.includes('resolveHandle'));
		expect(appviewCall).toContain('handle=a%20b%2Fc');
	});
});
