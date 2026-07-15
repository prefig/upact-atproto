// SPDX-License-Identifier: Apache-2.0
/**
 * The `@atproto/oauth-client-node` client and its metadata — the whole of the
 * OAuth machinery (PAR, PKCE, DPoP) lives behind this module.
 *
 * The client is a module-level singleton because its state and session stores
 * are in-memory and must span two separate requests: the `authorize` call that
 * begins the flow and the `callback` exchange that completes it. A fresh client
 * per request would lose the PKCE verifier and PAR state between them. This
 * constrains the package to single-instance node deployments (dev/sandbox); a
 * multi-process or Workers deployment needs shared stores first. Sessions are
 * revoked at authentication, so the session store never outlives one login.
 */

import {
	NodeOAuthClient,
	type NodeSavedSession,
	type NodeSavedState,
	type OAuthClientMetadataInput,
} from '@atproto/oauth-client-node';
import type { AtprotoConfig, AtprotoOAuthClient } from './types.js';

/** The single OAuth scope this adapter requests: ATProto identity + DPoP. */
export const ATPROTO_SCOPE: string = 'atproto';

const DEFAULT_CALLBACK_PATH = '/api/atproto/callback';

function isLoopback(baseUrl: string): boolean {
	try {
		const host = new URL(baseUrl).hostname;
		return host === '127.0.0.1' || host === '[::1]' || host === 'localhost';
	} catch {
		return false;
	}
}

function normaliseBaseUrl(baseUrl: string): string {
	return baseUrl.replace(/\/$/, '');
}

/**
 * The client metadata this deployment presents to authorization servers.
 * Public client (`token_endpoint_auth_method: 'none'`): no keys to manage, at
 * the cost of shorter-lived grants — the right trade while sign-in discards the
 * tokens anyway. Served at a public URL in production; the loopback form (dev)
 * is passed by value and never served.
 */
export function buildClientMetadata(config: AtprotoConfig): OAuthClientMetadataInput {
	const baseUrl = normaliseBaseUrl(config.baseUrl);
	const redirectUri = `${baseUrl}${config.callbackPath ?? DEFAULT_CALLBACK_PATH}`;
	const loopback = isLoopback(baseUrl);
	return {
		client_id: loopback
			? `http://localhost?redirect_uri=${encodeURIComponent(redirectUri)}&scope=${ATPROTO_SCOPE}`
			: `${baseUrl}/oauth/client-metadata.json`,
		client_name: config.clientName ?? 'upact',
		client_uri: config.clientUri ?? baseUrl,
		redirect_uris: [redirectUri],
		scope: ATPROTO_SCOPE,
		grant_types: ['authorization_code', 'refresh_token'],
		response_types: ['code'],
		application_type: loopback ? 'native' : 'web',
		token_endpoint_auth_method: 'none',
		dpop_bound_access_tokens: true,
	};
}

/** In-memory store spanning one authorize -> callback exchange (see header). */
function memoryStore<V>(): {
	set(key: string, value: V): Promise<void>;
	get(key: string): Promise<V | undefined>;
	del(key: string): Promise<void>;
} {
	const map = new Map<string, V>();
	return {
		async set(key: string, value: V): Promise<void> {
			map.set(key, value);
		},
		async get(key: string): Promise<V | undefined> {
			return map.get(key);
		},
		async del(key: string): Promise<void> {
			map.delete(key);
		},
	};
}

let cachedClient: NodeOAuthClient | null = null;
let cachedClientId: string | undefined;

/**
 * The module-singleton OAuth client for this deployment's config. Memoised by
 * `client_id`: a second call with the same config returns the same client (so
 * the state store spans authorize -> callback); a call with a different
 * `client_id` rebuilds it (config changed under the process).
 */
export function getClient(config: AtprotoConfig): AtprotoOAuthClient {
	const clientMetadata = buildClientMetadata(config);
	if (cachedClient && cachedClientId === clientMetadata.client_id) {
		return cachedClient as unknown as AtprotoOAuthClient;
	}
	cachedClient = new NodeOAuthClient({
		clientMetadata,
		stateStore: memoryStore<NodeSavedState>(),
		sessionStore: memoryStore<NodeSavedSession>(),
	});
	cachedClientId = clientMetadata.client_id;
	return cachedClient as unknown as AtprotoOAuthClient;
}
