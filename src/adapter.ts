// SPDX-License-Identifier: Apache-2.0
/**
 * createAtprotoAdapter — ATProto (Bluesky) sign-in adapter factory.
 *
 * Factory-only. Substrate state (the OAuth client, held as a module singleton
 * in client.ts; the injected client double, held in closure) is never on the
 * returned object (SPEC §7.5). Out-of-port extensions are typed as
 * AtprotoAdapterExtensions; consumers that only depend on the port interface
 * stay substrate-agnostic.
 *
 * The flow is redirect-shaped with a handle input:
 *   1. beginAuthorization(handle) -> URL (out-of-port; the "start" step — no
 *      credential exists yet, so it is NOT authenticate()). The client resolves
 *      handle -> DID -> PDS -> authorization server and returns the URL to send
 *      the browser to (PAR + PKCE + DPoP inside the client).
 *   2. authenticate(credential) — the TERMINAL callback exchange. `credential`
 *      is the authorization server's callback params. It runs `client.callback`,
 *      reads the DID, REVOKES the OAuth session (best-effort signOut), and
 *      resolves to an opaque Session wrapping the mapped Upactor.
 *
 * Authentication is not admission (cross-adapter-findings F7): a completed
 * authenticate() proves the person controls a DID, which anyone on the network
 * has. Whether they may enter the application is a separate fact the application
 * owns; this adapter never checks it and holds no admission state.
 *
 * Reading the resolved identity back (docs/decisions.md D1): authenticate()
 * returns the opaque Session per the port, and `upactorForSession` surfaces the
 * Upactor for that authentication. The adapter deliberately owns no application
 * session or cookie — the application binds its own session from the Upactor.
 */

import type { AuthError, IdentityPort, Session, Upactor } from '@prefig/upact';
import { createSession } from '@prefig/upact';
import { _unwrapSession } from '@prefig/upact/internal';
import { ATPROTO_SCOPE, getClient } from './client.js';
import { mapDidToUpactor } from './claims-mapper.js';
import type { AtprotoConfig, AtprotoCredential, AtprotoOAuthClient } from './types.js';

/** Out-of-port methods specific to the ATProto adapter. */
export interface AtprotoAdapterExtensions {
	/**
	 * Begins authorization for a member-entered handle (or DID): resolves it to
	 * an authorization server and returns the URL to send the browser to. The
	 * handle rides along as OAuth `state` (server-bound to this flow by the
	 * client's state store). The "start" step — no credential exists yet, so
	 * this is not authenticate(). Pattern: upact-oidc's buildAuthRedirect.
	 */
	beginAuthorization(handle: string): Promise<URL>;
	/**
	 * Surfaces the Upactor for a Session that authenticate() returned. Returns
	 * null for a Session this adapter did not produce (including any session
	 * created before a process restart, since the opaque-session table is
	 * process-local). This is how the application reads the resolved identity
	 * (opaque id, lifecycle, provenance) without the adapter owning any app
	 * session or cookie (docs/decisions.md D1).
	 */
	upactorForSession(session: Session): Upactor | null;
}

/** What the opaque Session holds (recovered only via _unwrapSession). */
interface AtprotoSessionData {
	upactor: Upactor;
}

/**
 * Creates an upact IdentityPort backed by ATProto sign-in.
 *
 * @param config - deployment coordinates (base URL, client-metadata labels).
 * @param _client - optional OAuth client override for testing; the module
 *   singleton in client.ts is used when omitted.
 */
export function createAtprotoAdapter(
	config: AtprotoConfig,
	_client?: AtprotoOAuthClient,
): IdentityPort & AtprotoAdapterExtensions {
	function client(): AtprotoOAuthClient {
		return _client ?? getClient(config);
	}

	// ——— IdentityPort ————————————————————————————————————————————————————————

	async function authenticate(credential: unknown): Promise<Session | AuthError> {
		if (!isAtprotoCredential(credential)) {
			return { code: 'credential_invalid', message: 'unrecognised credential shape' };
		}
		// The malformed-input check is deliberately before any client call, so a
		// callback missing its code costs no network round trip.
		if (!credential.params.get('code')) {
			return { code: 'credential_invalid', message: 'missing authorization code' };
		}

		let did: string;
		try {
			const { session } = await client().callback(credential.params);
			did = session.did;
			// Best-effort revocation: sign-in keeps no standing capability against
			// the member's repository. The DID has already been read.
			await session.signOut().catch(() => {});
		} catch (err) {
			return normaliseAtprotoError(err);
		}

		const upactor = mapDidToUpactor(did);
		const sessionData: AtprotoSessionData = { upactor };
		return createSession(sessionData);
	}

	async function currentUpactor(_request: Request): Promise<Upactor | null> {
		// The adapter carries no application-session machinery: the OAuth session
		// is revoked at authentication and the adapter holds nothing to consult on
		// a later request. The application owns its own session, bound from the
		// Upactor it read via upactorForSession (docs/decisions.md D1).
		return null;
	}

	async function invalidate(_session: Session): Promise<void> {
		// Nothing to revoke: the ATProto OAuth session was already revoked at
		// authentication (there is no standing credential), and the application
		// owns and clears its own session. Honest no-op.
	}

	async function issueRenewal(_identity: Upactor, _evidence: unknown): Promise<Upactor | null> {
		// ATProto sign-in has no represence semantics and no refresh channel this
		// adapter keeps: renewal is a fresh sign-in. Permanently null (SPEC §6.4
		// OPTIONAL).
		return null;
	}

	// ——— AtprotoAdapterExtensions ———————————————————————————————————————————

	async function beginAuthorization(handle: string): Promise<URL> {
		return client().authorize(handle, { scope: ATPROTO_SCOPE, state: handle });
	}

	function upactorForSession(session: Session): Upactor | null {
		const data = _unwrapSession<AtprotoSessionData>(session);
		return data === undefined ? null : data.upactor;
	}

	return { authenticate, currentUpactor, invalidate, issueRenewal, beginAuthorization, upactorForSession };
}

// ——— Internal helpers ————————————————————————————————————————————————————————

function isAtprotoCredential(value: unknown): value is AtprotoCredential {
	if (typeof value !== 'object' || value === null) return false;
	const candidate = value as { kind?: unknown; params?: unknown };
	return candidate.kind === 'atproto-callback' && candidate.params instanceof URLSearchParams;
}

/**
 * Normalises a `client.callback` failure into a port AuthError. The callback
 * exchange fails as one unit — a forged/expired code, a state that does not
 * match the flow's stored state, a DPoP/PKCE mismatch, or the authorization
 * server refusing the grant all surface here — so the classification leans on
 * substrate error strings, matching the OIDC adapter's mapping (findings G2).
 * A grant the server understood but refused is `credential_rejected`; a
 * transport failure reaching the PDS/authorization server is
 * `substrate_unavailable`; a rate-limit is `rate_limited`.
 */
export function normaliseAtprotoError(err: unknown): AuthError {
	const msg = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
	if (msg.includes('429') || msg.includes('rate') || msg.includes('slow_down')) {
		return { code: 'rate_limited', message: 'authorization server rate-limited' };
	}
	if (
		msg.includes('fetch') ||
		msg.includes('network') ||
		msg.includes('econnrefused') ||
		msg.includes('enotfound') ||
		msg.includes('timeout') ||
		msg.includes('socket') ||
		msg.includes('unavailable') ||
		msg.includes('502') ||
		msg.includes('503')
	) {
		return { code: 'substrate_unavailable', message: 'authorization server unavailable' };
	}
	// The default: the exchange was understood and refused (or otherwise did not
	// complete). dyad's inline provider mapped every callback failure to a single
	// rejection; the port's `credential_rejected` is that outcome.
	return { code: 'credential_rejected', message: 'authorization was not accepted' };
}
