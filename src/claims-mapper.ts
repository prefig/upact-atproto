// SPDX-License-Identifier: Apache-2.0
/**
 * Claims mapper — pure functions from a resolved DID to an opaque Upactor.
 *
 * Reads only the DID. No handle, no PDS host, no token, and no profile field
 * ever reaches the Upactor: sign-in learns the DID and nothing else, so there
 * is nothing else to strip (SPEC §7). The DID itself never rides on the
 * Upactor either — only its hash.
 *
 * Identifier derivation (cross-adapter-findings F11, the first shipped consumer
 * of the deferred Decision 7 `continuation`): `Upactor.id` = the first 32 hex
 * characters of SHA-256(did). The DID is the durable anchor; the PDS is only
 * its current host, so the id is stable across a PDS migration. This is
 * strictly stronger than the Mastodon adapter's per-instance actor-URL id (F3),
 * which does not survive an instance move. The derivation is a plain hash of
 * the portable identifier, opaque and non-reversible (SPEC §7.3).
 *
 * provenance.instance is the DID *method* (`did:plc`, `did:web`), not the PDS
 * or the authorization-server issuer, so provenance is as portable as the id:
 * a PDS migration changes neither (docs/decisions.md D3, citing F11).
 */

import { createHash } from 'node:crypto';
import type { Upactor } from '@prefig/upact';

/**
 * Opaque member id: the first 32 hex characters of SHA-256(did). Byte-identical
 * to a `crypto.subtle.digest('SHA-256', utf8(did))` derivation (the form dyad's
 * inline provider used before extraction), so ids are unchanged across the
 * seam. Stable across PDS migration; opaque and non-reversible at the port
 * boundary (SPEC §7.3, F11).
 */
export function deriveMemberId(did: string): string {
	return createHash('sha256').update(did, 'utf8').digest('hex').slice(0, 32);
}

/**
 * The DID method, used as `provenance.instance`. `did:plc:abc...` -> `did:plc`;
 * `did:web:example.com` -> `did:web`. Stable across PDS migration by
 * construction. Falls back to the whole DID for a malformed input.
 */
export function didMethod(did: string): string {
	const parts = did.split(':');
	return parts.length >= 2 ? `${parts[0]}:${parts[1]}` : did;
}

/**
 * Maps a resolved DID to an opaque Upactor.
 *
 * - `id`: SHA-256(did)[:32] — opaque, derived, portable across PDS migration.
 * - `capabilities`: empty. An ATProto sign-in carries neither an email channel
 *   nor an account-recovery path in the v0.1 vocabulary.
 * - `lifecycle`: `{ renewable: 'reauth' }`, no `expires_at`. The OAuth session
 *   is revoked at authentication and the adapter keeps no standing credential,
 *   so there is nothing to expire; renewal is a fresh sign-in (D2).
 * - `provenance`: `{ substrate: 'atproto', instance: <did method> }` (SPEC §4.4).
 * - No `display_hint`: the handle is discarded; only the DID is learned.
 */
export function mapDidToUpactor(did: string): Upactor {
	return {
		id: deriveMemberId(did),
		capabilities: new Set(),
		lifecycle: { renewable: 'reauth' },
		provenance: { substrate: 'atproto', instance: didMethod(did) },
	};
}
