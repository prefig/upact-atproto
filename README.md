# @prefig/upact-atproto

ATProto (Bluesky) adapter for [upact](https://github.com/prefig/upact).
Presents ATProto sign-in to an application as an upact `IdentityPort`: the
application resolves a member-entered handle to an authorization server, sends
the browser there, and on the callback receives an opaque, DID-derived
`Upactor` with the privacy minima the port guarantees. OAuth over
`@atproto/oauth-client-node` (PAR, PKCE, DPoP); the sign-in tokens are revoked
the moment the DID is read.

## What the adapter does

- **handle→DID resolution** (`resolveHandleToDid`): well-known first
  (authoritative for custom-domain handles), then the public AppView.
- **the OAuth client**: client metadata, in-memory state and session stores,
  and a module singleton spanning authorize→callback; PAR, PKCE, and DPoP all
  live inside the library.
- **`beginAuthorization(handle)`** starts the flow and returns the
  authorization URL to send the browser to.
- **`authenticate(callbackParams)`** completes it: runs the client's callback,
  reads the DID, revokes the OAuth session (best-effort `signOut`), and
  returns an opaque `Session` wrapping the mapped `Upactor`.
- **`upactorForSession(session)`** reads the resolved `Upactor` back out of
  that Session, so the application can run its own admission check and mint
  its own session.

Admission, waitlists, application session cookies, and the data store belong
to the consuming application; the adapter ends at the verified identity.

## Authentication and admission

A completed `authenticate()` proves the person controls a DID. Anyone on the
ATProto network has one, so authentication is universal and says nothing about
whether the person may enter your application. Admission is a separate fact
your application owns: check it against durable state on the callback, every
time. The OAuth `scope` the adapter requests is the fixed `'atproto'` identity
scope, unrelated to any application scope you grant.

This differs from a credential a community issues itself, where possession is
admission because the community controlled issuance. An ATProto credential is
open enrolment: treat it as proof of identity, and decide entry yourself.

## The member id survives a PDS move

`Upactor.id` = SHA-256(did) truncated to 32 hex characters. The DID is the
durable anchor and the PDS is only its current host, so the id is stable
across a PDS migration. The Mastodon adapter's per-instance actor-URL id does
not survive an instance move; a DID-derived id does.

`provenance.instance` is the DID *method* (`did:plc`, `did:web`), not the PDS
host, so provenance travels with the id. There is no `display_hint`: the
handle is passed to the authorization server as OAuth `state` and then
discarded, so the adapter learns the DID and no other attribute.

## Install

```
npm install @prefig/upact-atproto @prefig/upact @atproto/oauth-client-node
```

`@prefig/upact` and `@atproto/oauth-client-node` are peer dependencies.
Node 22 or later (required by the OAuth client).

## Usage

The application owns the HTTP surface and its own session; the adapter
exposes the substrate edge (the same shape as upact-oidc and upact-eudi).

```typescript
import { createAtprotoAdapter, resolveHandleToDid } from '@prefig/upact-atproto';

const port = createAtprotoAdapter({
  baseUrl: 'https://rp.example',        // determines redirect_uri + client_id
  clientName: 'my-app',                 // client-metadata label
});

// 1. Start: resolve the handle and send the browser to the authorization server.
const authorizeUrl = await port.beginAuthorization('alice.bsky.social');
// redirect the browser to authorizeUrl

// 2. Callback route: exchange the params, then run your admission + session.
const outcome = await port.authenticate({ kind: 'atproto-callback', params });
if ('code' in outcome) {
  // outcome is an AuthError: map it to your response
} else {
  const actor = port.upactorForSession(outcome)!;  // the resolved identity
  actor.id;                       // SHA-256(did)[:32], stable across a PDS move
  actor.provenance;               // { substrate: 'atproto', instance: 'did:plc' }
  actor.lifecycle;                // { renewable: 'reauth' }  (no standing credential)

  // Admission, waitlist, and session minting belong to your application:
  // e.g. if (await hasScopeGrant('atproto', actor.id, scope)) mintYourSession(actor.id);
}
```

`resolveHandleToDid`, `deriveMemberId`, `buildClientMetadata`, and `getClient`
are also exported for applications that need the resolution or client pieces
directly (for example, an admin route that resolves a handle to a member id
when granting a scope).

## Lifecycle

Sign-in exists to learn the DID. The OAuth session the callback produces is
revoked immediately (`signOut`), so the adapter keeps no access token, no
refresh token, and no DPoP key past the one `authenticate()` call. The
`Upactor` lifecycle reflects this: `renewable: 'reauth'` (renewal is one
redirect) with `expires_at` omitted rather than set (there is nothing to
expire). `issueRenewal` returns `null` unconditionally; `invalidate` is a
no-op. The id stays stable across sign-ins because it derives from the DID,
which outlives every session.

## Testing

`npm test` runs the unit suites (52 tests) against an injected OAuth client
double and a stubbed `fetch`, with no external processes. It covers handle→DID
resolution (both paths, unresolvable, URL-encoding), the callback exchange
happy path and each error path, the port methods, `beginAuthorization`,
`upactorForSession`, the claims mapper, the client metadata (web vs loopback),
and the sixteen-vector back-channel closure suite (SPEC §7.5). End-to-end
verification against a live PDS is deferred to the sandbox window.

## Further reading

- `CONFORMANCE.md`: the conformance statement (upact SPEC clauses, error
  mapping, evidence).
- `docs/decisions.md`: reading the identity back (D1), lifecycle (D2),
  identifier and provenance (D3), admission boundary and module singleton
  (D4), error normalisation (D5).

## Licence

Apache-2.0 (see `LICENSE`).
