# @prefig/upact-atproto

ATProto (Bluesky) sign-in adapter for [upact](https://github.com/prefig/upact).
Presents ATProto sign-in to an application as an upact `IdentityPort`: the
application resolves a member-entered handle to an authorization server, sends
the browser there, and — on the callback — receives an opaque, DID-derived
`Upactor` with the privacy minima the port guarantees. OAuth over
`@atproto/oauth-client-node` (PAR, PKCE, DPoP); the sign-in tokens are revoked
the moment the DID is read.

## What this owns: the substrate edge, and only that

This package is the extraction of the authentication half of dyad's inline
ATProto provider. It owns:

- **handle→DID resolution** (`resolveHandleToDid`): well-known first
  (authoritative for custom-domain handles), then the public AppView.
- **the OAuth client** (client metadata, in-memory state/session stores, the
  module singleton spanning authorize→callback); PAR, PKCE, and DPoP all live
  inside the library.
- **`beginAuthorization(handle)`** — the start step, an out-of-port extension.
  No credential exists yet, so it is deliberately *not* `authenticate()`
  (pattern: upact-oidc's `buildAuthRedirect`).
- **`authenticate(callbackParams)`** — the terminal exchange: it runs the
  client's callback, reads the DID, revokes the OAuth session (best-effort
  `signOut`), and returns an opaque `Session` wrapping the mapped `Upactor`.
- **`upactorForSession(session)`** — reads the resolved `Upactor` back out of
  that Session (see "Reading the identity back").

It does **not** own admission, waitlists, application session cookies, or
anything touching a data store. Those stay in the consuming application (in
dyad: `hasScopeGrant`, the pending-token flow, the HS256 `ScopeSession`,
Supabase). See "Not admission."

## Not admission (F7)

A completed `authenticate()` proves the person controls a DID. Anyone on the
ATProto network has one, so authentication is universal — it says nothing about
whether the person may enter your application. Admission is a separate fact your
application owns and must check itself, against durable state, on the callback
(F8). This adapter has no admission scope in its config and no code path that
gates on entitlement; the OAuth `scope` it requests is the fixed `'atproto'`
identity scope, unrelated to any application scope you grant.

This is the open-enrolment case (cross-adapter-findings F7), unlike a
closed-enrolment substrate where possession of the credential *is* admission
because the community issued it. An application that treats an ATProto sign-in
as admission is using this adapter against its design.

## Identity is portable, and stable

`Upactor.id` = SHA-256(did) truncated to 32 hex characters. This package is the
first shipped consumer of the deferred upact Decision 7 (`continuation`): the
DID is the durable anchor and the PDS is only its current host, so the id is
**stable across a PDS migration** (F11) — strictly stronger than the Mastodon
adapter's per-instance actor-URL id, which does not survive an instance move.

`provenance.instance` is the DID *method* (`did:plc`, `did:web`), not the PDS
host, so provenance is as portable as the id. There is no `display_hint`: the
handle is passed to the authorization server as OAuth `state` and then
discarded — the adapter learns the DID and nothing else.

## Install (local)

This package consumes `@prefig/upact` (npm) and wraps
`@atproto/oauth-client-node` (peer dependency).

```
npm install
npm run build      # tsc -> dist/
npm test           # vitest: resolution, callback exchange, mapper, 16-vector closure (52 tests)
npm run typecheck
```

## Usage

The application owns the HTTP surface and its own session; the adapter exposes
the substrate edge (pattern: upact-oidc / upact-eudi).

```typescript
import { createAtprotoAdapter, resolveHandleToDid } from '@prefig/upact-atproto';

const port = createAtprotoAdapter({
  baseUrl: 'https://rp.example',        // determines redirect_uri + client_id
  clientName: 'my-app',                 // client-metadata label
});

// 1. Start: resolve the handle and send the browser to the authorization server.
const authorizeUrl = await port.beginAuthorization('alice.bsky.social');
// redirect the browser to authorizeUrl

// 2. Callback route: exchange the params, then run YOUR admission + session.
const outcome = await port.authenticate({ kind: 'atproto-callback', params });
if ('code' in outcome) {
  // outcome is an AuthError — map it to your response
} else {
  const actor = port.upactorForSession(outcome)!;  // the resolved identity
  actor.id;                       // SHA-256(did)[:32] — stable, portable
  actor.provenance;               // { substrate: 'atproto', instance: 'did:plc' }
  actor.lifecycle;                // { renewable: 'reauth' }  (no standing credential)

  // Admission, waitlist, session minting: YOUR territory, not the adapter's.
  // e.g. if (await hasScopeGrant('atproto', actor.id, scope)) mintYourSession(actor.id);
}
```

`resolveHandleToDid`, `deriveMemberId`, `buildClientMetadata`, and `getClient`
are also exported for applications that need the resolution or client pieces
directly (dyad's admin scope-granting route resolves a handle to a member id
this way).

## Lifecycle: no standing credential

Sign-in exists to learn the DID. The OAuth session the callback produces is
revoked immediately (`signOut`), so the adapter keeps no access token, no
refresh token, and no DPoP key past the one `authenticate()` call. The `Upactor`
lifecycle reflects this: `renewable: 'reauth'` (renewal is one redirect) with
`expires_at` omitted rather than set (there is nothing to expire). `issueRenewal`
returns `null` unconditionally; `invalidate` is an honest no-op. That the id is
still stable across sign-ins comes from the DID, not from anything the adapter
stores.

## Testing

`npm test` runs the unit suites (52 tests) against an injected OAuth client
double and a stubbed `fetch` — no external processes. It covers handle→DID
resolution (both paths, unresolvable, URL-encoding), the callback exchange happy
path and each error path, the honest-null port methods, `beginAuthorization`,
`upactorForSession`, the claims mapper, the client metadata (web vs loopback),
and the sixteen-vector back-channel closure suite (SPEC §7.5). End-to-end
verification against a live PDS is deferred to the sandbox window.

## Further reading

- `CONFORMANCE.md`: the conformance statement (upact SPEC clauses, error
  mapping, evidence).
- `docs/decisions.md`: reading the identity back (D1), lifecycle (D2),
  identifier and provenance (D3), not-admission + module singleton (D4), error
  normalisation (D5).

## Licence

Apache-2.0 (see `LICENSE`).
