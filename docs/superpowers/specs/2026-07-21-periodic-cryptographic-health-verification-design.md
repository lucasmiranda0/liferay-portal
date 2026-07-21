# Periodic Cryptographic Health Verification — Design

- **Jira:** LPD-93272 (Story) / LPD-97652 (Technical Task, branch target)
- **Epic:** LPD-93270 (FIPS Level 1 Requirements)
- **Date:** 2026-07-21
- **Author:** Lucas Miranda

## Problem

Long-running Liferay DXP instances have no way to re-verify the cryptographic
subsystem without a restart. The validated FIPS provider runs its self-tests
only at startup. DXP needs an authenticated REST endpoint that re-triggers those
provider self-tests on demand — callable by a human Crypto Officer or by an
external scheduler (AWS EventBridge, GCP Cloud Scheduler, cron) — and that
transitions the node into an Error State on failure.

## Goal

Provide an authenticated REST endpoint that forces the validated provider to
re-run its self-tests on demand and, on failure, stops cryptographic operations,
enters a persistent Error State, and emits a critical FIPS audit event.

## Locked Decisions

1. **Error State** — a persistent, process-wide gate flag in `FIPSModeValidator`.
   Once set, crypto-guarded operations refuse until the JVM is restarted
   (restart-only recovery, matching FIPS 140-3 error-state semantics).

1. **Self-test mechanism** — force the validated provider to re-run its own
   Known Answer Tests (KATs). This is the ticket-faithful reading ("re-trigger
   *them*", "provider self-test re-verification"). No app-level battery
   substitute — see Risks.

1. **Authorization** — a new "Crypto Officer" regular role backed by a
   company-scoped portal resource action. One permission check authorizes both
   the human and the OAuth2 client-credentials service account.

1. **Testing** — Layer A only for this deliverable: unit tests (service, gate,
   audit, permission) plus integration tests for REST auth wiring on a normal
   bundle. Layer B (genuine BC-FIPS KAT re-run on a FIPS-booted JVM) is deferred
   until the FIPS CI environment (LPD-80674, still Open) exists.

1. **No feature flag** — no existing FIPS code uses one; `fips.enabled` already
   makes the endpoint inert (returns `NOT_APPLICABLE`), so it is the natural
   gate.

## Existing Building Blocks

- `portal-kernel/src/com/liferay/portal/kernel/security/fips/FIPSModeValidator.java`
  — boot-time FIPS enforcement. Reflectively checks `CryptoServicesRegistrar`,
  `FipsStatus.isReady()`/`getStatusMessage()` (BCFIPS) and `assertHealthy()`
  (Amazon Corretto); holds `validateAlgorithm(String)` and
  `validateKey(String, int)` allow-list guards. Invoked once from
  `ModuleFrameworkImpl.initFramework()` when `PropsValues.FIPS_ENABLED` is set.
- `PropsValues.FIPS_ENABLED` / portal property `fips.enabled` (default `false`).
- Crypto consumers already routing through `FIPSModeValidator.validate*`:
  `EncryptorImpl`, `DigesterUtil`, the password encryptors.
- Audit pipeline: `com.liferay.portal.kernel.audit.AuditMessage`,
  `AuditMessageFactoryUtil`, `AuditRouterUtil.route(AuditMessage)`; router impl
  in `portal-security-audit-router`.
- OAuth2 client-credentials: `ClientProfile.HEADLESS_SERVER`,
  `GrantType.CLIENT_CREDENTIALS`, requests execute as the application's
  `clientCredentialUserId`.
- REST template: `headless-portal-instances-impl` (system/admin-scoped,
  imperative `PermissionChecker` authorization).

There is no pre-existing on-demand self-test, FIPS error state, FIPS audit
event, "Crypto Officer" role, or FIPS REST module — all greenfield.

## Architecture (Approach A: kernel core + REST Builder module)

The Error State gate must live where crypto is guarded, so the core sits in
portal-kernel and the user-facing surface sits in a new module cluster.

```
Crypto Officer (browser session)  ─┐
                                   ├─▶ POST /o/crypto-health/v1.0/health-verifications
OAuth2 client-credentials caller ─┘         │ (JAX-RS whiteboard authenticates; PermissionThreadLocal set)
                                            ▼
                          HealthVerificationResourceImpl
                            1. check Crypto Officer resource action
                            2. FIPSModeValidator.runSelfTests()  ──▶ kernel: force provider KAT re-run
                            3. on failure: kernel sets error-state flag; resource routes periodic-health-failure audit event
                            4. return HealthVerification DTO (200 / 409 / 503)
```

### Portal core (Ant, restart-based deploy)

`portal-kernel/src/com/liferay/portal/kernel/security/fips/`

- **`FIPSModeValidator`** (extended):
  - `public static FIPSHealthCheckResult runSelfTests()` — new re-invocable
    entry point.
    - If `!PropsValues.FIPS_ENABLED`, returns a `NOT_APPLICABLE` result
      (re-verifying an inactive provider is meaningless).
    - Otherwise forces the validated provider to re-execute its KATs, then
      re-runs the existing approved-mode / `FipsStatus.isReady()` (BCFIPS) or
      `assertHealthy()` (Corretto) checks.
    - On failure, captures which check/test failed, the FIPS state string, the
      provider exception message, and the provider name into
      `FIPSHealthCheckResult`, transitions to the error state, and returns
      `healthy = false`. On success returns `healthy = true`.
    - Guarded by a lock so concurrent calls neither run KATs concurrently nor
      race the flag.
  - Persistent error state:
    - `private static volatile boolean _fipsErrorState;`
    - `public static boolean isInErrorState();`
    - `validateAlgorithm(...)` and `validateKey(...)` gain a first-line check:
      if `_fipsErrorState`, throw `SecurityException` ("FIPS error state —
      cryptographic operations are halted"). Because the kernel crypto paths
      already route through these guards, the gate reaches every one of them.
    - Set-once; no public clear method (restart-only recovery).
  - Test seam: the provider interaction is delegated through a small injectable
    function/interface so unit tests can inject a fake pass/fail/throw and reset
    the flag without a FIPS-booted JVM. This is a deliberate, minimal departure
    from the class's all-static style.
- **`FIPSHealthCheckResult`** (new, immutable): `status`
  (`HEALTHY`/`FAILED`/`NOT_APPLICABLE`), `providerName`, `failedTest`,
  `fipsState`, `providerMessage`. Returned by the kernel; mapped by the module
  to the audit event and the HTTP response.

### New OSGi module cluster

`modules/apps/portal-security/`, package base
`com.liferay.portal.security.fips.rest`:

```
portal-security-fips-rest-api      (generated REST API)
portal-security-fips-rest-impl     (resource impl, Crypto Officer role/action, audit emission)
portal-security-fips-rest-client   (generated client)
portal-security-fips-rest-test     (integration tests)
```

Built with REST Builder (`rest-config.yaml` + `rest-openapi.yaml` drive
generation; only the resource impl is hand-written).

## REST API

`rest-config.yaml`: `apiPackagePath: com.liferay.portal.security.fips.rest`;
`application.baseURI: /crypto-health`; `className: CryptoHealthApplication`;
`name: Liferay.Crypto.Health.REST`; `javaEEPackage: jakarta`;
`forcePredictableOperationId: true`.

**Operation** — one non-idempotent POST (it re-runs self-tests and can halt the
node, so POST, not GET):

```
POST /o/crypto-health/v1.0/health-verifications
  tags: [HealthVerification]   → generates HealthVerificationResource
  operationId: postHealthVerification
  request body: none
  responses:
    200 → HealthVerification
```

**Response DTO `HealthVerification`:**

| Property | Type | Notes |
| ----------------- | ------------------- | ---------------------------------------- |
| `status` | string (enum) | `HEALTHY`, `FAILED`, `NOT_APPLICABLE` |
| `date` | string (date-time) | when the verification ran |
| `providerName` | string | e.g. `BCFIPS` |
| `failedTest` | string | populated only on failure |
| `fipsState` | string | provider FIPS state string at failure |
| `providerMessage` | string | provider exception message on failure |

**HTTP semantics enforced by the resource impl:**

- **200** + `HEALTHY` — self-tests re-ran and passed.
- **409 Conflict** + `NOT_APPLICABLE` — `fips.enabled` is off.
- **503 Service Unavailable** + `FAILED` — self-test failure; returned *after*
  the error state is set and the audit event emitted. 503 communicates
  "crypto subsystem is now halted" to the scheduler better than a 200-with-body.

## Authorization

**Resource action.**
`portal-security-fips-rest-impl/src/main/resources/resource-actions/default.xml`
defines a portal-scoped model resource `com.liferay.portal.security.fips` with
action key `TRIGGER_HEALTH_VERIFICATION`, wired via the `resource.actions.configs`
pattern. Constants in `FIPSActionKeys`.

**Crypto Officer role.** A `PortalInstanceLifecycleListener` in the impl module
creates a regular role named `Crypto Officer` per company if absent and grants
it `TRIGGER_HEALTH_VERIFICATION` at company scope — the standard pattern for
shipping a default role. The role display name key is added to the global
`Language.properties`.

**Check in the resource impl** (imperative, per the `headless-portal-instances`
template):

```java
PermissionChecker permissionChecker = PermissionThreadLocal.getPermissionChecker();

if (!PortalPermissionUtil.contains(
        permissionChecker, FIPSActionKeys.TRIGGER_HEALTH_VERIFICATION)) {

    throw new PrincipalException.MustHavePermission(
        permissionChecker, FIPSActionKeys.TRIGGER_HEALTH_VERIFICATION);
}
```

**Both callers, one check:**

- *Human* — a logged-in user granted the Crypto Officer role;
  `PermissionThreadLocal` is populated by the session.
- *Scheduler (NPE)* — an admin registers an OAuth2 application (Headless Server
  profile, `client_credentials` grant) whose `clientCredentialUserId` is a
  service-account user granted the Crypto Officer role, and grants the app the
  OAuth2 scope for the `Liferay.Crypto.Health.REST` application. The request
  executes as that service user, so the identical check passes. No second code
  path.

The OAuth2 application and service-account user are admin configuration, not
code. The deliverable only makes the single role/action work for both; the
scheduler setup is documented in the runbook below.

## Audit Event

Emitted from the resource impl on failure, via the kernel audit pipeline
(`AuditMessageFactoryUtil` + `AuditRouterUtil.route(...)`):

- `eventType` = `"periodic-health-failure"`.
- `timestamp` — set by the factory.
- `className` = `FIPSModeValidator.class.getName()`; `userId`/`userName` = the
  triggering principal.
- `additionalInfo` JSON:

  ```json
  {
    "severity": "CRITICAL",
    "failedTest": "...",
    "fipsState": "...",
    "providerMessage": "...",
    "providerName": "BCFIPS"
  }
  ```

  `AuditMessage` has no native severity field, so `severity: CRITICAL` rides in
  `additionalInfo`.

## Error Handling

On failure the sequence follows the AC ("crypto stopped → Error State →
audit"):

1. `runSelfTests()` detects failure → kernel sets the error-state flag first
   (crypto now halted).

1. Resource emits the `periodic-health-failure` audit event.

1. Resource returns 503 + `FAILED` with the failure fields populated.

Edge cases:

- **Fail-closed on an unverifiable check.** If the KAT re-run mechanism itself
  errors (e.g., the reflective invocation throws), "unable to complete the
  self-test" is treated as a self-test failure → error state + audit + 503. FIPS
  reads inability-to-prove-health as not-healthy.
- **Concurrent triggers.** `runSelfTests()` is lock-guarded.
- **Already in error state.** If the node is already halted, return 503 +
  `FAILED` immediately (message notes it is already in error state) without
  re-running.
- **Audit routing failure.** If `route(...)` throws `AuditException`, log it; do
  not swallow the 503 or unwind the error state — a lost audit record must not
  resurrect crypto.

## Testing

Layer A only (Layer B deferred with LPD-80674):

**Unit tests** — extend
`portal-kernel/test/unit/.../fips/FIPSModeValidatorTest.java`, driving the
injectable self-test seam so no FIPS JVM is needed:

- `runSelfTests()` returns `NOT_APPLICABLE` when `fips.enabled` is off.
- Success path → `healthy = true`, flag stays clear.
- Failure path (fake reports failure) → flag set;
  `FIPSHealthCheckResult` carries `failedTest`/`fipsState`/`providerMessage`.
- Fail-closed path (fake throws) → flag set.
- Gate: `validateAlgorithm`/`validateKey` throw once the flag is set;
  `isInErrorState()` reflects it.
- Concurrency guard holds.

**Module unit tests** — `HealthVerificationResourceImpl` maps the kernel result
to DTO + status code (200/409/503), and constructs the `AuditMessage` correctly
(`eventType`, `additionalInfo`) with a mock `AuditRouter`.

**Integration tests** — `portal-security-fips-rest-test`, on a normal
(non-FIPS) bundle:

- Unauthorized caller (no Crypto Officer role) → 403.
- Authorized caller, FIPS disabled → 409 / `NOT_APPLICABLE`.

This exercises REST wiring + role bootstrap + permission check + the 409 branch
without a FIPS provider.

Coverage boundary: the failure logic (error-state transition, audit content, 503
mapping) *is* covered by unit tests via the fake seam. Only the genuine BC-FIPS
KAT re-run against a real FIPS-booted JVM is deferred to Layer B.

## Rollout / Deploy

1. `Language.properties` edit + `buildLang` (Crypto Officer role name).

1. Kernel: `ant deploy install-portal-snapshot` + server restart.

1. Module cluster: `gradlew deploy` from the api/impl/client modules.

1. Runbook: because recovery is restart-only, operational recovery from an Error
   State is "fix the underlying crypto issue, then restart the node." The
   external scheduler is configured by registering an OAuth2 client-credentials
   application (Headless Server profile) whose service-account user holds the
   Crypto Officer role and whose app is granted the
   `Liferay.Crypto.Health.REST` scope.

## Risks

- **BC-FIPS KAT re-run hook.** Forcing the provider to re-run its self-tests
  assumes the installed `bc-fips` jar exposes a stable entry point to do so;
  `FipsStatus` largely reports status rather than re-running power-on
  self-tests. The exact reflective symbol will be pinned against the actual jar
  during implementation. If no such hook exists there is no ticket-faithful
  implementation, and the choice (accept a documented app-level-battery
  deviation, pin a bc-fips version that exposes a hook, or reshape the ticket)
  returns to the ticket owner rather than being silently substituted.
- **Kernel test seam.** Adding an injectable seam to an all-static kernel class
  is a small style departure, accepted to make the gate unit-testable without a
  FIPS JVM.
- **Real-provider verification gap.** Until LPD-80674 provisions the FIPS CI
  environment, the genuine KAT re-run and real-failure behavior are verified
  only by the injectable-fake unit tests, not against a live FIPS provider.

## Out of Scope

- The FIPS CI environment itself (LPD-80674).
- Any scheduled/automatic invocation — the endpoint is on-demand; scheduling is
  the external caller's responsibility.
- Automatic recovery from Error State without a restart.