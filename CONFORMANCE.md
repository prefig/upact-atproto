# Conformance: @prefig/upact-atproto

**Spec version:** upact v0.1.2
**Package version:** 0.1.0
**Date:** 2026-07-15

## Substrate

ATProto (Bluesky) sign-in, spoken to as an OAuth client via
`@atproto/oauth-client-node`. Redirect-shaped with a handle input: the member
enters a handle (or DID); the adapter resolves it to an authorization server and
returns the URL to send the browser to (PAR + PKCE + DPoP, all inside the
client library); the authorization server redirects the browser back with a
`code`, which the adapter exchanges for the resolved DID and then immediately
revokes. The whole OAuth machinery lives behind the client module; the package
adds handle→DID resolution, the client metadata, the authorization start, the
terminal exchange, and the mapping from DID to an opaque `Upactor`.

This is the enforcement camp (adapter-shapes.md): the substrate exposes an
account and repository the adapter deliberately does not touch. It is also the
second direct adapter of the multi-instance fediverse shape (after Mastodon),
and the first shipped consumer of the deferred Decision 7 (`continuation`):
DID-based identity is portable across PDS migration.

**Not admission (F7).** A completed `authenticate()` proves control of a DID.
Anyone on the network has one, so authentication is universal and says nothing
about whether the person may enter the consuming application. Admission is a
separate, application-held fact this package never checks. See README, "Not
admission."

## Threat model

The authorization server (the member's PDS entryway) is trusted to attest
control of the DID; the client library verifies the OAuth response (PKCE, DPoP,
state binding via its state store). The adapter does not defend against a
compromised PDS or a malicious authorization server, and it establishes no
sybil resistance: one person can complete `authenticate()` for any DID they
control, and DIDs are free to create. Deduplication and admission belong to the
application. Single-instance deployment posture (D4): the in-memory OAuth state
store binds a flow to the process that began it.

## Capabilities self-declared

`[]`: no capabilities declared. The v0.1 vocabulary is `email | recovery`
(SPEC §5.1); an ATProto sign-in carries neither an email channel nor an
account-recovery path this adapter surfaces (F1: capability absence is the
feature, not a gap).

## Lifecycle and provenance

Every `Upactor` returned by this adapter carries:

- `lifecycle.expires_at`: omitted. Sign-in keeps no standing credential — the
  OAuth session is revoked at authentication — so there is nothing to expire
  (D2; the F6 deliberately-absent-TTL shape).
- `lifecycle.renewable`: always `'reauth'`. Renewal is a fresh sign-in.
- `provenance.substrate`: `'atproto'`.
- `provenance.instance`: the DID *method* (`did:plc`, `did:web`), not the PDS
  host or the authorization-server `iss`, so provenance is as portable as the
  id (D3, citing F11).

## AuthError mapping table

| Substrate result | AuthErrorCode |
|---|---|
| Unrecognised credential shape (not `{ kind: 'atproto-callback', params }`) | `credential_invalid` |
| Callback params missing the `code` (checked before any client call) | `credential_invalid` |
| Callback exchange refused/failed: bad or expired code, `state` mismatch, DPoP/PKCE failure, `invalid_grant`, `access_denied` | `credential_rejected` |
| Transport failure reaching the PDS / authorization server (fetch/network/ECONNREFUSED/timeout/502/503) | `substrate_unavailable` |
| Authorization server rate-limit (`429`) | `rate_limited` |

`identity_unavailable` and `auth_failed` are not emitted: the substrate
surfaces no identity-existence distinction, and the catch-all is the honest
`credential_rejected` (D5, mirroring the OIDC mapping, findings G2).

## Session opacity (SPEC §7.4)

This adapter uses `createSession` from `@prefig/upact`. The Session opaquely
holds only the mapped `Upactor`; the resolved DID never appears on it (only its
hash, as `Upactor.id`), and no OAuth token is ever placed in it (the tokens are
revoked before `authenticate()` returns). Recovery is via `_unwrapSession`
inside the adapter only, surfaced to the application through the
`upactorForSession` extension (D1). `invalidate` is an honest no-op: the OAuth
session was already revoked, and the application owns and clears its own
session.

## Reading the resolved identity (out-of-port, D1)

`upactorForSession(session)` returns the `Upactor` for a Session that
`authenticate()` produced (or `null` for a foreign/pre-restart Session). This is
how the application reads the opaque id, lifecycle, and provenance right after
authentication — to run its own admission check and mint its own session —
without the adapter owning any application cookie. It mirrors eudi's
`redeemResponseCode` minus the response-code storage, because ATProto's callback
exchange and the application's establish handler are the same request (no second
browser hop to bridge). The OIDC cookie-jar session-ownership model is
deliberately not adopted: the application's session carries admission scope,
which is application territory (F8).

## Adapter back-channel closure (SPEC §7.5)

Passes a 16-vector reflection test at `tests/back-channel.test.ts`, parity with
the sibling adapters. Sentinel values for the resolved DID and the OAuth
client's internals are verified unreachable through JSON.stringify, Object.keys,
Object.getOwnPropertyNames, Reflect.ownKeys, Object.getOwnPropertySymbols,
for-in, structuredClone (throws), util.inspect, direct property access by likely
names (`config`, the SPEC §7.5-named `client`, `did`, `_client`), spread,
replacer-wrapped stringify, and Object.entries; a final vector asserts the
opaque Session does not surface the DID either. The OAuth client is a module
singleton held outside the adapter object; the injected client double is held in
closure. The DID lives only inside the process-local opaque-session WeakMap.

## Identifier derivation (SPEC §4.4, §7.3; Decision 7 / F11)

`Upactor.id` = the first 32 hex characters of SHA-256(did). Stable across PDS
migration because the DID is the durable anchor (F11); opaque and
non-reversible (§7.3). Cross-session recognition is offered (the id is stable),
unlike eudi's one-shot id: ATProto has a durable public identifier where the
German PID under a predicate-only declaration does not. No handle, PDS host, or
token enters the derivation.

## display_hint

Never populated. The handle is passed to the authorization server as OAuth
`state` and then discarded; the adapter learns the DID and nothing else, and a
handle is reassignable so it would be a poor display key even if kept (D3).

## Deviations from SHOULD clauses

- **`currentUpactor` always returns `null` and never throws
  `SubstrateUnavailableError`.** The adapter carries no application-session
  machinery: the OAuth session is revoked at authentication, so no later request
  bears an adapter-managed session to consult. The application owns its session,
  bound from the Upactor it read via `upactorForSession`. The error type is
  re-exported for API symmetry with the sibling adapters.
- **§8 transparent refresh is not applicable.** There is no refresh channel the
  adapter retains; renewal is a fresh sign-in.

## issueRenewal

Normatively OPTIONAL (SPEC §6.4). Permanently returns `null`: ATProto sign-in
has no represence semantics and the adapter keeps no refresh channel;
re-presentation is a fresh `authenticate()` producing the same (stable) id.

## Conformance evidence

`npm test` runs the unit suites (52 tests): handle→DID resolution (well-known
then AppView fallback, unresolvable, URL-encoding), the callback exchange happy
path and each error path, the honest-null port methods, `beginAuthorization`,
`upactorForSession`, the claims mapper (id stability, DID-method provenance, no
display_hint, no expires_at, DID never on the Upactor), the client metadata
(web vs loopback), and the 16-vector back-channel closure suite. All run against
an injected OAuth client double and a stubbed `fetch`; there are no external
processes. End-to-end verification against a live PDS is the true check and is
deferred to the sandbox window.
