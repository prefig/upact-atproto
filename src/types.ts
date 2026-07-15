// SPDX-License-Identifier: Apache-2.0
/**
 * Public types for @prefig/upact-atproto.
 *
 * The adapter owns the ATProto substrate edge only: handle -> DID resolution,
 * the `@atproto/oauth-client-node` client (client metadata, DPoP/PAR/PKCE), the
 * authorization start, and the terminal callback exchange. It knows nothing of
 * admission, waitlists, or any application session; those are the consuming
 * application's territory (SPEC §-, cross-adapter-findings F7).
 */

/** Configuration for createAtprotoAdapter and the client-metadata builder. */
export interface AtprotoConfig {
	/**
	 * Public base URL of the deployment. Determines the `redirect_uri`
	 * (`<baseUrl>/api/atproto/callback`) and the client-metadata `client_id`.
	 * A loopback IP literal (`http://127.0.0.1:<port>`, `http://[::1]:<port>`)
	 * selects the OAuth loopback client for local development; the ATProto
	 * OAuth spec requires a loopback IP literal, not `localhost`.
	 */
	baseUrl: string;
	/** `client_name` in the client metadata. Default: `'upact'`. */
	clientName?: string;
	/** `client_uri` in the client metadata. Default: `baseUrl`. */
	clientUri?: string;
	/**
	 * Path (relative to `baseUrl`) the authorization server redirects the
	 * browser back to. Default: `/api/atproto/callback`.
	 */
	callbackPath?: string;
}

/**
 * The terminal credential accepted by createAtprotoAdapter's authenticate():
 * the authorization server's callback query parameters (`code`, `state`,
 * `iss`, and any `error`/`error_description`), exactly as delivered to the
 * application's callback route. The start phase (resolving the handle and
 * building the authorization URL) is exposed via `beginAuthorization`, an
 * out-of-port method on the adapter (pattern: upact-oidc's buildAuthRedirect).
 */
export type AtprotoCredential = { kind: 'atproto-callback'; params: URLSearchParams };

/**
 * The subset of `@atproto/oauth-client-node`'s OAuthSession the adapter reads:
 * the resolved DID and the best-effort revocation hook. Everything else the
 * session carries (tokens, DPoP keys, the PDS agent) stays inside the client.
 */
export interface AtprotoOAuthSession {
	readonly did: string;
	signOut(): Promise<void>;
}

/**
 * The subset of the `@atproto/oauth-client-node` client the adapter depends on.
 * Declared structurally so tests can inject a double and so consumers never
 * couple to the concrete `NodeOAuthClient`. The real client is created and held
 * as a module singleton inside the package (client.ts); PAR, PKCE, and DPoP all
 * live behind this seam.
 */
export interface AtprotoOAuthClient {
	authorize(input: string, options: { scope: string; state: string }): Promise<URL>;
	callback(
		params: URLSearchParams,
	): Promise<{ session: AtprotoOAuthSession; state?: string | null }>;
}
