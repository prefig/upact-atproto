// SPDX-License-Identifier: Apache-2.0
/**
 * @prefig/upact-atproto — ATProto (Bluesky) sign-in adapter for upact.
 *
 * Presents ATProto sign-in to an application as an upact IdentityPort. Owns the
 * substrate edge only: handle -> DID resolution, the
 * `@atproto/oauth-client-node` client (client metadata, PAR/PKCE/DPoP), the
 * authorization start, and the terminal callback exchange. The OAuth session is
 * revoked at authentication; the adapter keeps no tokens and no application
 * session.
 *
 * Authentication is not admission (cross-adapter-findings F7): a completed
 * authenticate() proves control of a DID, nothing about whether the person may
 * enter the application. The first shipped consumer of Decision 7
 * (`continuation`): the member id is SHA-256(did)[:32], stable across PDS
 * migration (F11).
 */

export { createAtprotoAdapter, normaliseAtprotoError } from './adapter.js';
export type { AtprotoAdapterExtensions } from './adapter.js';

export { resolveHandleToDid, APPVIEW_RESOLVE_URL, RESOLVE_TIMEOUT_MS } from './resolve.js';

export { deriveMemberId, didMethod, mapDidToUpactor } from './claims-mapper.js';

export { buildClientMetadata, getClient, ATPROTO_SCOPE } from './client.js';

export type {
	AtprotoConfig,
	AtprotoCredential,
	AtprotoOAuthClient,
	AtprotoOAuthSession,
} from './types.js';

export type {
	Upactor,
	IdentityLifecycle,
	Capability,
	Session,
	AuthError,
	AuthErrorCode,
	IdentityPort,
} from '@prefig/upact';
export { SubstrateUnavailableError } from '@prefig/upact';
