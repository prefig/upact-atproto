// SPDX-License-Identifier: Apache-2.0
/**
 * Handle -> DID resolution, the substrate's discovery step.
 *
 * Well-known first (authoritative for custom-domain handles), then the public
 * AppView as fallback. DNS TXT resolution is deliberately skipped: it needs a
 * node dns runtime, and every handle these two paths miss is one the OAuth flow
 * could not sign in anyway. Carried unchanged from dyad's inline provider,
 * which is now a thin wrapper over this package.
 */

/** The public Bluesky AppView used as the resolution fallback. */
export const APPVIEW_RESOLVE_URL: string =
	'https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle';

/** Per-request timeout for a resolution fetch (milliseconds). */
export const RESOLVE_TIMEOUT_MS: number = 5000;

/**
 * Resolves an ATProto handle to its DID, or null if it does not resolve.
 * Well-known first, then the public AppView.
 */
export async function resolveHandleToDid(handle: string): Promise<string | null> {
	try {
		const res = await fetch(`https://${handle}/.well-known/atproto-did`, {
			signal: AbortSignal.timeout(RESOLVE_TIMEOUT_MS),
		});
		if (res.ok) {
			const text = (await res.text()).trim();
			if (text.startsWith('did:')) return text;
		}
	} catch {
		// fall through to the AppView
	}
	try {
		const res = await fetch(
			`${APPVIEW_RESOLVE_URL}?handle=${encodeURIComponent(handle)}`,
			{ signal: AbortSignal.timeout(RESOLVE_TIMEOUT_MS) },
		);
		if (res.ok) {
			const body = (await res.json()) as { did?: unknown };
			if (typeof body.did === 'string') return body.did;
		}
	} catch {
		// unresolvable
	}
	return null;
}
