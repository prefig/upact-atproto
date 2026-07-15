# Decisions

## D1. Reading the resolved identity back without owning an application session

Date: 2026-07-15. Status: decided.

The problem the split forced. This package owns the ATProto substrate edge; the
consuming application (dyad, the first) owns admission and its own session. The
application needs the resolved opaque member id right after authentication to
run its admission check (`hasScopeGrant`) and to mint its own session, but the
port's `authenticate()` returns an opaque `Session` (SPEC §7.4) whose contents
are, by contract, not decomposable by the application. So returning the Session
alone is not enough: the application cannot read the id out of it.

Two precedents were weighed:

- **upact-oidc**: the adapter owns the session. `authenticate()` writes an
  HMAC-signed session cookie into an injected cookie jar, and `currentUpactor`
  reads it back on later requests. Session ownership lives in the adapter.
- **upact-eudi**: the adapter owns *no* application session. `authenticate()`
  returns the opaque Session, and a single-use `redeemResponseCode` extension
  hands the application the `Upactor` once — because the wallet-follow arrives
  as a *separate* browser request to the finish path, so the mapped Upactor
  must be parked under a code between the two requests.

Decision: follow the eudi shape, not the OIDC shape. The OIDC cookie-jar model
is disqualified by the split — dyad's session carries admission scope, which is
application territory (F8: authorization must be re-validated against durable
state per request), and moving it into the adapter is exactly what the split
must prevent. So the adapter must own no application cookie.

But eudi's response-code indirection buys nothing here: ATProto's callback
exchange and the application's establish handler are the *same* request (the
authorization server redirects the browser straight to the callback route,
which runs the exchange inline). There is no second browser hop to bridge. So
the minimal eudi-parity surface is: `authenticate()` returns the opaque Session
wrapping the mapped `Upactor`, and a synchronous out-of-port extension,
`upactorForSession(session)`, recovers that `Upactor` via
`_unwrapSession` — the same controlled boundary crossing eudi's
`redeemResponseCode` makes, minus the storage and the single-use ceremony a
same-request flow does not need. The adapter holds no per-authentication state
at all: nothing to sweep, nothing to invalidate, no cookie. `upactorForSession`
returns `null` for any Session this process did not produce (the opaque-session
table is a process-local WeakMap).

The application flow is therefore: `authenticate(callbackParams)` →
`Session | AuthError`; on success, `upactorForSession(session)` → `Upactor`;
the application reads `upactor.id`, runs its own admission gate, and mints its
own session. The adapter never sees the admission decision or the app session.

## D2. Lifecycle: no standing credential, so `renewable: 'reauth'` and no `expires_at`

Date: 2026-07-15. Status: decided.

ATProto sign-in in this package exists to learn the DID and nothing more. The
OAuth session the callback exchange produces is revoked immediately
(`session.signOut()`, best-effort) once the DID has been read; the adapter
keeps no access token, no refresh token, and no DPoP key past the single
`authenticate()` call. There is therefore no credential with a standing
lifetime to expire.

So the `Upactor` lifecycle is modelled as *no standing credential*:
`renewable: 'reauth'` (renewal is a fresh sign-in, one redirect), and
`expires_at` is omitted rather than set — the F6 distinction between an
explicit TTL, a deliberately-absent TTL, and an unset-by-oversight one. There
is no represence semantics (`'represence'` is for presence-renewed substrates)
and the identity is not permanent (`'never'`), so `'reauth'` is the honest
value. `issueRenewal` returns `null` unconditionally: there is no refresh
channel the adapter retains, and re-presentation is a fresh `authenticate()`
producing the same id (D3).

That the id is nonetheless stable and portable across sign-ins — despite the
adapter keeping no credential — is the point of D3: stability comes from the
DID, not from anything the adapter stores.

## D3. Identifier and provenance derive from the DID (Decision 7 `continuation`, F11)

Date: 2026-07-15. Status: decided.

`Upactor.id` = the first 32 hex characters of SHA-256(did). This package is the
first shipped consumer of the deferred upact Decision 7 (`continuation`,
cross-adapter-findings F11): the DID is the durable anchor and the PDS is only
its current host, so the id is stable across a PDS migration. This is strictly
stronger than the Mastodon adapter's per-instance actor-URL id (F3), which does
not survive an instance move. The derivation is a plain hash of the portable
identifier — opaque and non-reversible at the port boundary (SPEC §7.3). It is
byte-identical to the `crypto.subtle` derivation dyad's inline provider used
before extraction, so ids are unchanged across the seam.

`provenance.instance` is the DID *method* (`did:plc`, `did:web`), not the PDS
host and not the authorization-server `iss`. The reasoning is F11 again: if
`instance` were the PDS, it would change on migration while the id stayed
fixed, and the "portable identity" story would be self-contradicting on its own
provenance field. The DID method is as stable as the id, so provenance is as
portable as the id: a PDS migration changes neither. `substrate` is `'atproto'`.

No `display_hint`: the handle the member typed is passed to the authorization
server as OAuth `state` and then discarded — the adapter learns the DID and
nothing else. A handle is also not stable (it can be reassigned), so it would
be a poor display key even if kept. Cross-session recognition is offered (the
id is stable), unlike eudi's one-shot id; the difference is that ATProto has a
durable public identifier and the German PID, under a predicate-only
declaration, does not.

## D4. Authentication is not admission (F7); the client is a module singleton (carried from dyad)

Date: 2026-07-15. Status: decided.

**Not admission.** A completed `authenticate()` proves the person controls a
DID. Anyone on the ATProto network has one, so this says nothing about whether
they may enter the consuming application (F7: open-enrolment substrate).
Admission is a separate, application-held fact. This package therefore contains
no admission check, no waitlist/pending flow, no session minting, and nothing
touching the application's data store — all of that stays in the application
(in dyad: `hasScopeGrant`, the pending-token cookie dance, the HS256
`ScopeSession`, Supabase). The package's `AtprotoConfig` has no admission scope
field; the ATProto OAuth `scope` it requests is the fixed `'atproto'` identity
scope, unrelated to any application scope slug.

**Module singleton.** The `@atproto/oauth-client-node` client is a module-level
singleton (client.ts), carried unchanged from dyad's inline provider. Its state
and session stores are in-memory and must span two separate requests: the
`authorize` call (begin) and the `callback` exchange (terminal). A fresh client
per request would lose the PKCE verifier and PAR state between them.
Consequence, stated plainly: single-instance node deployments only
(dev/sandbox); a multi-process or Workers deployment needs shared stores first.
The client is memoised by `client_id`, so the application constructing a fresh
adapter per request (dyad does) still shares one underlying client. The
singleton is not reachable from the returned adapter (§7.5 closure test).

## D5. Error normalisation mirrors the OIDC mapping (G2)

Date: 2026-07-15. Status: decided.

The callback exchange fails as one unit — a forged or expired code, a `state`
that does not match the flow's stored state, a DPoP/PKCE mismatch, or the
authorization server refusing the grant all surface as a thrown error from
`client.callback`. There is no structured error code to branch on, so
classification leans on substrate error strings, matching the OIDC adapter's
mapping (findings G2): a transport failure reaching the PDS or authorization
server is `substrate_unavailable`; a rate-limit (`429`) is `rate_limited`;
everything else the server understood and refused is `credential_rejected`. A
malformed credential (unrecognised shape, or a callback missing its `code`) is
`credential_invalid`, checked before any client call so it costs no network
round trip. `identity_unavailable` and `auth_failed` are not emitted: the
substrate surfaces no identity-existence distinction, and the catch-all is the
honest `credential_rejected` (dyad's inline provider mapped every callback
failure to a single rejection, which this preserves).
