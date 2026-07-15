import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { deriveMemberId, didMethod, mapDidToUpactor } from '../src/index.js';

const PLC = 'did:plc:abcdefghijklmnopqrstuvwx';
const WEB = 'did:web:alice.example.com';

describe('deriveMemberId', () => {
	it('is the first 32 hex chars of SHA-256(did)', () => {
		const expected = createHash('sha256').update(PLC, 'utf8').digest('hex').slice(0, 32);
		expect(deriveMemberId(PLC)).toBe(expected);
	});

	it('is 32 lowercase hex characters', () => {
		expect(deriveMemberId(PLC)).toMatch(/^[0-9a-f]{32}$/);
	});

	it('matches a Web Crypto SHA-256 derivation (parity with dyad pre-extraction)', async () => {
		const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(PLC));
		const webCrypto = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0'))
			.join('')
			.slice(0, 32);
		expect(deriveMemberId(PLC)).toBe(webCrypto);
	});

	it('is stable for the same DID across calls (F11: id survives PDS migration)', () => {
		expect(deriveMemberId(PLC)).toBe(deriveMemberId(PLC));
	});

	it('differs for different DIDs', () => {
		expect(deriveMemberId(PLC)).not.toBe(deriveMemberId(WEB));
	});
});

describe('didMethod', () => {
	it('extracts did:plc', () => {
		expect(didMethod(PLC)).toBe('did:plc');
	});
	it('extracts did:web', () => {
		expect(didMethod(WEB)).toBe('did:web');
	});
	it('falls back to the whole value for a malformed did', () => {
		expect(didMethod('garbage')).toBe('garbage');
	});
});

describe('mapDidToUpactor', () => {
	const upactor = mapDidToUpactor(PLC);

	it('sets id to the derived member id', () => {
		expect(upactor.id).toBe(deriveMemberId(PLC));
	});

	it('declares no capabilities', () => {
		expect(upactor.capabilities.size).toBe(0);
	});

	it('has no display_hint (the handle is discarded, only the DID is learned)', () => {
		expect(upactor.display_hint).toBeUndefined();
	});

	it('lifecycle is reauth with no expires_at (no standing credential)', () => {
		expect(upactor.lifecycle).toEqual({ renewable: 'reauth' });
		expect(upactor.lifecycle?.expires_at).toBeUndefined();
	});

	it('provenance names the substrate and the DID method as instance', () => {
		expect(upactor.provenance).toEqual({ substrate: 'atproto', instance: 'did:plc' });
	});

	it('never carries the raw DID anywhere on the Upactor', () => {
		expect(JSON.stringify(upactor, (_k, v) => (v instanceof Set ? [...v] : v))).not.toContain(PLC);
	});
});
