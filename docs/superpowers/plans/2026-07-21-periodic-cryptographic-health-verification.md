# Periodic Cryptographic Health Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose an authenticated REST endpoint that forces the validated FIPS provider to re-run its self-tests on demand and, on failure, halts cryptographic operations, enters a persistent Error State, and emits a critical FIPS audit event.

**Architecture:** The Error State gate lives in the portal-kernel class `FIPSModeValidator` (the chokepoint every crypto path already calls), which gains a re-invocable `runSelfTests()` and a process-wide error-state flag. The provider interaction sits behind a swappable `FIPSSelfTestExecutor` seam so the gate is unit-testable without a FIPS JVM. A new REST Builder module cluster under `modules/apps/portal-security/` exposes the endpoint, enforces a new "Crypto Officer" resource action (serving both a human and an OAuth2 client-credentials service account), and emits the audit event.

**Tech Stack:** Java (portal-kernel, Ant build), OSGi + Gradle (REST Builder / JAX-RS whiteboard), JUnit 4 + Mockito (unit), Arquillian (integration), BouncyCastle FIPS / Amazon Corretto provider (reflective).

## Global Constraints

- Ticket prefix for every commit: `LPD-97652` (title format `LPD-97652 <sentence-case summary>`, no trailing period, under 72 chars).
- Every new source file starts with the SPDX header exactly as in existing kernel files:

  ```
  /**
   * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
   * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
   */
  ```
- `@author Lucas Miranda` on every new type.
- Run the `format-source` skill before each commit; the formatter's edits are part of the commit.
- Language keys go ONLY in the global file `modules/apps/portal-language/portal-language-lang/src/main/resources/content/Language.properties`, kept alphabetical; regenerate with `buildLang`.
- No feature flag — `fips.enabled` (`PropsValues.FIPS_ENABLED`) is the gate.
- Recovery from Error State is restart-only; never add a public method that clears the flag.
- REST Builder: never hand-edit `@Generated("")` files; author YAML, commit, run `buildREST`, commit generated output.
- bnd/Gradle dependency versions are copied verbatim from `.claude/rules/rest-builder.md`.

---

### Task 1: Kernel value types (result, exception, executor seam)

Pure, dependency-free types the rest of the kernel work builds on. Fully unit-testable.

**Files:**
- Create: `portal-kernel/src/com/liferay/portal/kernel/security/fips/FIPSHealthCheckResult.java`
- Create: `portal-kernel/src/com/liferay/portal/kernel/security/fips/FIPSSelfTestException.java`
- Create: `portal-kernel/src/com/liferay/portal/kernel/security/fips/FIPSSelfTestExecutor.java`
- Test: `portal-kernel/test/unit/com/liferay/portal/kernel/security/fips/FIPSHealthCheckResultTest.java`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `FIPSHealthCheckResult` with nested `enum Status { HEALTHY, FAILED, NOT_APPLICABLE }` and static factories `healthy(String providerName)`, `failed(String providerName, String failedTest, String fipsState, String providerMessage)`, `notApplicable()`; getters `getStatus()`, `getProviderName()`, `getFailedTest()`, `getFipsState()`, `getProviderMessage()`.
  - `FIPSSelfTestException(String providerName, String failedTest, String fipsState, String providerMessage)` extends `Exception`; getters `getProviderName()`, `getFailedTest()`, `getFipsState()`, `getProviderMessage()`.
  - `FIPSSelfTestExecutor` functional interface: `String execute() throws Exception` (returns provider name on success; throws `FIPSSelfTestException` on a detected self-test failure; any other exception = unverifiable/fail-closed).

- [ ] **Step 1: Write the failing test**

`FIPSHealthCheckResultTest.java`:

```java
/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.security.fips;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Lucas Miranda
 */
public class FIPSHealthCheckResultTest {

	@Test
	public void testFailed() {
		FIPSHealthCheckResult result = FIPSHealthCheckResult.failed(
			"BCFIPS", "AES-KAT", "ERROR", "boom");

		Assert.assertEquals(
			FIPSHealthCheckResult.Status.FAILED, result.getStatus());
		Assert.assertEquals("BCFIPS", result.getProviderName());
		Assert.assertEquals("AES-KAT", result.getFailedTest());
		Assert.assertEquals("ERROR", result.getFipsState());
		Assert.assertEquals("boom", result.getProviderMessage());
	}

	@Test
	public void testHealthy() {
		FIPSHealthCheckResult result = FIPSHealthCheckResult.healthy("BCFIPS");

		Assert.assertEquals(
			FIPSHealthCheckResult.Status.HEALTHY, result.getStatus());
		Assert.assertEquals("BCFIPS", result.getProviderName());
		Assert.assertNull(result.getFailedTest());
	}

	@Test
	public void testNotApplicable() {
		FIPSHealthCheckResult result = FIPSHealthCheckResult.notApplicable();

		Assert.assertEquals(
			FIPSHealthCheckResult.Status.NOT_APPLICABLE, result.getStatus());
	}

}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ant test-class -Dtest.class=FIPSHealthCheckResultTest`
Expected: FAIL — `FIPSHealthCheckResult` does not compile/exist.

- [ ] **Step 3: Write minimal implementation**

`FIPSSelfTestExecutor.java`:

```java
/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.security.fips;

/**
 * @author Lucas Miranda
 */
public interface FIPSSelfTestExecutor {

	/**
	 * Forces the validated provider to re-run its self-tests and re-verifies
	 * approved mode. Returns the provider name on success. Throws {@link
	 * FIPSSelfTestException} on a detected self-test failure; any other
	 * exception signals an unverifiable state and is treated as failure
	 * (fail-closed) by the caller.
	 */
	public String execute() throws Exception;

}
```

`FIPSSelfTestException.java`:

```java
/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.security.fips;

/**
 * @author Lucas Miranda
 */
public class FIPSSelfTestException extends Exception {

	public FIPSSelfTestException(
		String providerName, String failedTest, String fipsState,
		String providerMessage) {

		super(providerMessage);

		_providerName = providerName;
		_failedTest = failedTest;
		_fipsState = fipsState;
		_providerMessage = providerMessage;
	}

	public String getFailedTest() {
		return _failedTest;
	}

	public String getFipsState() {
		return _fipsState;
	}

	public String getProviderMessage() {
		return _providerMessage;
	}

	public String getProviderName() {
		return _providerName;
	}

	private final String _failedTest;
	private final String _fipsState;
	private final String _providerMessage;
	private final String _providerName;

}
```

`FIPSHealthCheckResult.java`:

```java
/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.security.fips;

/**
 * @author Lucas Miranda
 */
public class FIPSHealthCheckResult {

	public static FIPSHealthCheckResult failed(
		String providerName, String failedTest, String fipsState,
		String providerMessage) {

		return new FIPSHealthCheckResult(
			Status.FAILED, providerName, failedTest, fipsState,
			providerMessage);
	}

	public static FIPSHealthCheckResult healthy(String providerName) {
		return new FIPSHealthCheckResult(
			Status.HEALTHY, providerName, null, null, null);
	}

	public static FIPSHealthCheckResult notApplicable() {
		return new FIPSHealthCheckResult(
			Status.NOT_APPLICABLE, null, null, null, null);
	}

	public String getFailedTest() {
		return _failedTest;
	}

	public String getFipsState() {
		return _fipsState;
	}

	public String getProviderMessage() {
		return _providerMessage;
	}

	public String getProviderName() {
		return _providerName;
	}

	public Status getStatus() {
		return _status;
	}

	public enum Status {

		FAILED, HEALTHY, NOT_APPLICABLE

	}

	private FIPSHealthCheckResult(
		Status status, String providerName, String failedTest, String fipsState,
		String providerMessage) {

		_status = status;
		_providerName = providerName;
		_failedTest = failedTest;
		_fipsState = fipsState;
		_providerMessage = providerMessage;
	}

	private final String _failedTest;
	private final String _fipsState;
	private final String _providerMessage;
	private final String _providerName;
	private final Status _status;

}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ant test-class -Dtest.class=FIPSHealthCheckResultTest`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add portal-kernel/src/com/liferay/portal/kernel/security/fips/FIPSHealthCheckResult.java \
        portal-kernel/src/com/liferay/portal/kernel/security/fips/FIPSSelfTestException.java \
        portal-kernel/src/com/liferay/portal/kernel/security/fips/FIPSSelfTestExecutor.java \
        portal-kernel/test/unit/com/liferay/portal/kernel/security/fips/FIPSHealthCheckResultTest.java
git commit -m "LPD-97652 Add FIPS self-test result, exception, and executor seam"
```

---

### Task 2: Kernel error-state gate and `runSelfTests()`

The core behavior: re-invocable self-test that transitions to a persistent error state on failure, and crypto guards that refuse once the flag is set. Unit-tested by swapping the executor seam via `ReflectionTestUtil` — no FIPS JVM required.

**Files:**
- Modify: `portal-kernel/src/com/liferay/portal/kernel/security/fips/FIPSModeValidator.java`
- Test: `portal-kernel/test/unit/com/liferay/portal/kernel/security/fips/FIPSModeValidatorTest.java` (extend existing)

**Interfaces:**
- Consumes: `FIPSHealthCheckResult`, `FIPSSelfTestException`, `FIPSSelfTestExecutor` (Task 1).
- Produces:
  - `public static FIPSHealthCheckResult FIPSModeValidator.runSelfTests()`
  - `public static boolean FIPSModeValidator.isInErrorState()`
  - Private swappable field `_fipsSelfTestExecutor` (non-final) and `_fipsErrorState` (volatile), both mutable via `ReflectionTestUtil` in tests.
  - `validateAlgorithm(String)` / `validateKey(String, int)` throw `SecurityException` ("FIPS error state - cryptographic operations are halted") when the flag is set.

- [ ] **Step 1: Write the failing tests**

Append to `FIPSModeValidatorTest.java` (add imports `com.liferay.portal.kernel.security.fips.FIPSHealthCheckResult` is same package; add `import com.liferay.portal.kernel.test.ReflectionTestUtil;` already present):

```java
	@Test
	public void testRunSelfTestsFailureEntersErrorState() {
		try (SafeCloseable safeCloseable =
				PropsValuesTestUtil.swapWithSafeCloseable(
					"FIPS_ENABLED", true)) {

			_swapExecutor(
				() -> {
					throw new FIPSSelfTestException(
						"BCFIPS", "AES-KAT", "ERROR", "integrity failure");
				});

			FIPSHealthCheckResult result = FIPSModeValidator.runSelfTests();

			Assert.assertEquals(
				FIPSHealthCheckResult.Status.FAILED, result.getStatus());
			Assert.assertEquals("AES-KAT", result.getFailedTest());
			Assert.assertTrue(FIPSModeValidator.isInErrorState());

			_assertSecurityException(
				"cryptographic operations are halted",
				() -> FIPSModeValidator.validateAlgorithm("AES"));
			_assertSecurityException(
				"cryptographic operations are halted",
				() -> FIPSModeValidator.validateKey("AES", 128));
		}
		finally {
			_resetErrorState();
		}
	}

	@Test
	public void testRunSelfTestsFailsClosedOnUnexpectedError() {
		try (SafeCloseable safeCloseable =
				PropsValuesTestUtil.swapWithSafeCloseable(
					"FIPS_ENABLED", true)) {

			_swapExecutor(
				() -> {
					throw new RuntimeException("reflection blew up");
				});

			FIPSHealthCheckResult result = FIPSModeValidator.runSelfTests();

			Assert.assertEquals(
				FIPSHealthCheckResult.Status.FAILED, result.getStatus());
			Assert.assertTrue(FIPSModeValidator.isInErrorState());
		}
		finally {
			_resetErrorState();
		}
	}

	@Test
	public void testRunSelfTestsNotApplicableWhenFIPSDisabled() {
		try (SafeCloseable safeCloseable =
				PropsValuesTestUtil.swapWithSafeCloseable(
					"FIPS_ENABLED", false)) {

			FIPSHealthCheckResult result = FIPSModeValidator.runSelfTests();

			Assert.assertEquals(
				FIPSHealthCheckResult.Status.NOT_APPLICABLE, result.getStatus());
			Assert.assertFalse(FIPSModeValidator.isInErrorState());
		}
	}

	@Test
	public void testRunSelfTestsSuccess() {
		try (SafeCloseable safeCloseable =
				PropsValuesTestUtil.swapWithSafeCloseable(
					"FIPS_ENABLED", true)) {

			_swapExecutor(() -> "BCFIPS");

			FIPSHealthCheckResult result = FIPSModeValidator.runSelfTests();

			Assert.assertEquals(
				FIPSHealthCheckResult.Status.HEALTHY, result.getStatus());
			Assert.assertEquals("BCFIPS", result.getProviderName());
			Assert.assertFalse(FIPSModeValidator.isInErrorState());
		}
		finally {
			_resetErrorState();
		}
	}

	private void _resetErrorState() {
		ReflectionTestUtil.setFieldValue(
			FIPSModeValidator.class, "_fipsErrorState", false);
	}

	private void _swapExecutor(FIPSSelfTestExecutor fipsSelfTestExecutor) {
		ReflectionTestUtil.setFieldValue(
			FIPSModeValidator.class, "_fipsSelfTestExecutor",
			fipsSelfTestExecutor);
	}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `ant test-class -Dtest.class=FIPSModeValidatorTest`
Expected: FAIL — `runSelfTests`, `isInErrorState`, and the `_fipsSelfTestExecutor`/`_fipsErrorState` fields do not exist.

- [ ] **Step 3: Modify `FIPSModeValidator`**

Add the error-state guard at the very top of `validateAlgorithm` and `validateKey` (before the existing `FIPS_ENABLED` early return). In `validateAlgorithm`:

```java
	public static void validateAlgorithm(String algorithm) {
		_checkErrorState();

		if (!PropsValues.FIPS_ENABLED) {
			return;
		}
		// ... existing body unchanged ...
	}
```

In `validateKey`:

```java
	public static void validateKey(String algorithm, int keySize) {
		_checkErrorState();

		if (!PropsValues.FIPS_ENABLED) {
			return;
		}
		// ... existing body unchanged ...
	}
```

Add these public methods (after `validateKey`):

```java
	public static boolean isInErrorState() {
		return _fipsErrorState;
	}

	public static FIPSHealthCheckResult runSelfTests() {
		if (!PropsValues.FIPS_ENABLED) {
			return FIPSHealthCheckResult.notApplicable();
		}

		synchronized (_selfTestLock) {
			if (_fipsErrorState) {
				return FIPSHealthCheckResult.failed(
					null, "already-in-error-state", null,
					"FIPS is already in error state");
			}

			try {
				String providerName = _fipsSelfTestExecutor.execute();

				return FIPSHealthCheckResult.healthy(providerName);
			}
			catch (FIPSSelfTestException fipsSelfTestException) {
				_fipsErrorState = true;

				return FIPSHealthCheckResult.failed(
					fipsSelfTestException.getProviderName(),
					fipsSelfTestException.getFailedTest(),
					fipsSelfTestException.getFipsState(),
					fipsSelfTestException.getProviderMessage());
			}
			catch (Exception exception) {
				_fipsErrorState = true;

				return FIPSHealthCheckResult.failed(
					null, "self-test-execution", null,
					exception.getMessage());
			}
		}
	}
```

Add the private guard (near the other private methods):

```java
	private static void _checkErrorState() {
		if (_fipsErrorState) {
			throw new SecurityException(
				"FIPS error state - cryptographic operations are halted");
		}
	}
```

Add fields (in the private-field block at the bottom, alphabetized with the existing ones). `_fipsSelfTestExecutor` is intentionally non-`final` so tests can swap it via `ReflectionTestUtil`:

```java
	private static volatile boolean _fipsErrorState;
	private static FIPSSelfTestExecutor _fipsSelfTestExecutor =
		new ReflectionFIPSSelfTestExecutor();
	private static final Object _selfTestLock = new Object();
```

> NOTE: `ReflectionFIPSSelfTestExecutor` does not exist until Task 3. To keep this task compiling and green on its own, add a temporary inline default here and replace it in Task 3:
> ```java
> private static FIPSSelfTestExecutor _fipsSelfTestExecutor =
>     () -> {
>         throw new FIPSSelfTestException(
>             null, "not-implemented", null,
>             "Reflective executor not yet wired");
>     };
> ```
> The unit tests always swap the executor, so this placeholder never runs in tests. Task 3 replaces it with the real `new ReflectionFIPSSelfTestExecutor()`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `ant test-class -Dtest.class=FIPSModeValidatorTest`
Expected: PASS (existing 5 tests + 4 new).

- [ ] **Step 5: Commit**

```bash
git add portal-kernel/src/com/liferay/portal/kernel/security/fips/FIPSModeValidator.java \
        portal-kernel/test/unit/com/liferay/portal/kernel/security/fips/FIPSModeValidatorTest.java
git commit -m "LPD-97652 Add on-demand FIPS self-test and error-state gate"
```

---

### Task 3: Reflective self-test executor (real provider interaction)

The production `FIPSSelfTestExecutor` that re-verifies the provider and forces its self-tests to re-run. This mirrors the reflective logic already in `_validateFIPSProvider`. It cannot be unit-tested (no FIPS provider on the unit classpath) — this is the deferred Layer B boundary from the spec; verification here is compile + code review, with real-provider validation deferred until the FIPS CI environment (LPD-80674) exists.

**Files:**
- Create: `portal-kernel/src/com/liferay/portal/kernel/security/fips/ReflectionFIPSSelfTestExecutor.java`
- Modify: `portal-kernel/src/com/liferay/portal/kernel/security/fips/FIPSModeValidator.java` (swap the placeholder default)

**Interfaces:**
- Consumes: `FIPSSelfTestExecutor`, `FIPSSelfTestException` (Task 1).
- Produces: package-private `ReflectionFIPSSelfTestExecutor implements FIPSSelfTestExecutor`, wired as the default `_fipsSelfTestExecutor`.

- [ ] **Step 1: Create `ReflectionFIPSSelfTestExecutor`**

```java
/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.security.fips;

import com.liferay.petra.reflect.ReflectionUtil;
import com.liferay.portal.kernel.util.GetterUtil;

import java.lang.reflect.Method;

import java.security.Provider;
import java.security.Security;

import java.util.Objects;

/**
 * Re-runs the validated provider's self-tests on demand. BCFIPS and Amazon
 * Corretto are driven reflectively so portal-kernel keeps no compile-time
 * dependency on the provider jars.
 *
 * @author Lucas Miranda
 */
public class ReflectionFIPSSelfTestExecutor implements FIPSSelfTestExecutor {

	@Override
	public String execute() throws Exception {
		Provider[] providers = Security.getProviders();

		if ((providers == null) || (providers.length == 0)) {
			throw new FIPSSelfTestException(
				null, "provider-presence", null,
				"There are no security providers");
		}

		Provider provider = providers[0];

		String name = provider.getName();

		if (Objects.equals(name, "AmazonCorrettoCryptoProvider")) {
			_reverifyAmazonCorretto(provider);
		}
		else if (Objects.equals(name, "BCFIPS")) {
			_reverifyBCFIPS(provider);
		}
		else {
			throw new FIPSSelfTestException(
				name, "provider-identity", null,
				"The first security provider is not an allowed FIPS provider");
		}

		return name;
	}

	private void _reverifyAmazonCorretto(Provider provider)
		throws FIPSSelfTestException {

		try {
			Class<?> providerClass = provider.getClass();

			Method assertHealthyMethod = ReflectionUtil.getDeclaredMethod(
				providerClass, "assertHealthy");

			assertHealthyMethod.invoke(provider);
		}
		catch (Exception exception) {
			throw new FIPSSelfTestException(
				"AmazonCorrettoCryptoProvider", "assertHealthy", null,
				_rootMessage(exception));
		}
	}

	private void _reverifyBCFIPS(Provider provider)
		throws FIPSSelfTestException {

		try {
			ClassLoader classLoader = provider.getClass().getClassLoader();

			Class<?> cryptoServicesRegistrarClass = Class.forName(
				"org.bouncycastle.crypto.CryptoServicesRegistrar", true,
				classLoader);
			Class<?> fipsStatusClass = Class.forName(
				"org.bouncycastle.crypto.fips.FipsStatus", true, classLoader);

			// Force the module self-tests (KATs) to run again. The exact
			// symbol is confirmed against the installed bc-fips jar during
			// the FIPS CI verification step below.

			Method runSelfTestsMethod = ReflectionUtil.getDeclaredMethod(
				fipsStatusClass, "runSelfTests");

			runSelfTestsMethod.invoke(null);

			Method isInApprovedOnlyModeMethod =
				ReflectionUtil.getDeclaredMethod(
					cryptoServicesRegistrarClass, "isInApprovedOnlyMode");

			if (!GetterUtil.getBoolean(
					isInApprovedOnlyModeMethod.invoke(null))) {

				throw new FIPSSelfTestException(
					"BCFIPS", "approved-only-mode", "NOT_APPROVED",
					"BCFIPS is not in approved only mode");
			}

			Method isReadyMethod = ReflectionUtil.getDeclaredMethod(
				fipsStatusClass, "isReady");

			if (!GetterUtil.getBoolean(isReadyMethod.invoke(null))) {
				Method getStatusMessageMethod =
					ReflectionUtil.getDeclaredMethod(
						fipsStatusClass, "getStatusMessage");

				throw new FIPSSelfTestException(
					"BCFIPS", "integrity-self-test",
					String.valueOf(getStatusMessageMethod.invoke(null)),
					"BCFIPS integrity self test failed");
			}
		}
		catch (FIPSSelfTestException fipsSelfTestException) {
			throw fipsSelfTestException;
		}
		catch (Exception exception) {
			throw new FIPSSelfTestException(
				"BCFIPS", "self-test-invocation", null,
				_rootMessage(exception));
		}
	}

	private String _rootMessage(Throwable throwable) {
		Throwable causeThrowable = throwable.getCause();

		if (causeThrowable == null) {
			causeThrowable = throwable;
		}

		String message = causeThrowable.getMessage();

		if (message == null) {
			return causeThrowable.toString();
		}

		return message;
	}

}
```

> RISK (from the spec): `FipsStatus.runSelfTests()` is the assumed hook to force a KAT re-run. If the installed `bc-fips` version exposes no such method (or names it differently), `ReflectionUtil.getDeclaredMethod` throws, `execute()` wraps it as a `FIPSSelfTestException("self-test-invocation")`, and — under the fail-closed policy — the node enters Error State on every call. That is safe but wrong-behaving. **Do not silently substitute an app-level battery.** Confirm the real symbol during the verification step and, if absent, escalate to the ticket owner (accept a documented app-level-battery deviation, pin a bc-fips version that exposes a hook, or reshape the ticket).

- [ ] **Step 2: Wire it as the default executor**

In `FIPSModeValidator`, replace the Task 2 placeholder lambda with:

```java
	private static FIPSSelfTestExecutor _fipsSelfTestExecutor =
		new ReflectionFIPSSelfTestExecutor();
```

- [ ] **Step 3: Verify compilation and existing tests still pass**

Run: `ant test-class -Dtest.class=FIPSModeValidatorTest`
Expected: PASS (all 9 tests — they swap the executor, so the reflective default never runs).

> Real-provider verification (BCFIPS `runSelfTests` symbol, real approved-mode, induced-failure → Error State) is DEFERRED to Layer B and cannot be confirmed in this environment. Record this explicitly on the ticket: the reflective path is code-reviewed and compiles, but is unverified against a live FIPS provider until LPD-80674 exists.

- [ ] **Step 4: Deploy the kernel change (manual, required before the module tasks build against it)**

Run:

```bash
cd /home/me/dev/projects/liferay-portal/portal-kernel && ANT_OPTS="-Xmx2560m" ant deploy install-portal-snapshot
```

Then restart the server (see `.claude/rules/tomcat.md` Bounce). This publishes the new kernel API so the module cluster can compile against `FIPSModeValidator.runSelfTests()` and `FIPSHealthCheckResult`.

- [ ] **Step 5: Commit**

```bash
git add portal-kernel/src/com/liferay/portal/kernel/security/fips/ReflectionFIPSSelfTestExecutor.java \
        portal-kernel/src/com/liferay/portal/kernel/security/fips/FIPSModeValidator.java
git commit -m "LPD-97652 Add reflective FIPS self-test executor"
```

---

### Task 4: Scaffold the REST Builder module cluster

Author the hand-written files for all four modules, then run REST Builder to generate the API, client, and base resource. Follows `.claude/rules/rest-builder.md` exactly.

**Files (create — hand-written):**
- `modules/apps/portal-security/portal-security-fips-rest-api/{.lfrbuild-portal, bnd.bnd, build.gradle}`
- `modules/apps/portal-security/portal-security-fips-rest-impl/{.lfrbuild-portal, bnd.bnd, build.gradle, rest-config.yaml, rest-openapi.yaml}`
- `modules/apps/portal-security/portal-security-fips-rest-client/{.lfrbuild-portal, bnd.bnd, build.gradle}`
- `modules/apps/portal-security/portal-security-fips-rest-test/{bnd.bnd, build.gradle}`

**Interfaces:**
- Consumes: nothing (independent of kernel tasks at author time).
- Produces (after `buildREST`): generated `com.liferay.portal.security.fips.rest.dto.v1_0.HealthVerification`, generated `BaseHealthVerificationResourceImpl` with method `public HealthVerification postHealthVerification() throws Exception`, generated `CryptoHealthApplication`, and a scaffolded (empty-override) `HealthVerificationResourceImpl`.

- [ ] **Step 1: Author `portal-security-fips-rest-api`**

`.lfrbuild-portal`: empty file.

`bnd.bnd`:

```
Bundle-Name: Liferay Crypto Health REST API
Bundle-SymbolicName: com.liferay.portal.security.fips.rest.api
Bundle-Version: 1.0.0
Export-Package:\
	com.liferay.portal.security.fips.rest.dto.v1_0,\
	com.liferay.portal.security.fips.rest.resource.v1_0
```

`build.gradle`:

```
dependencies {
	compileOnly group: "com.fasterxml.jackson.core", name: "jackson-annotations", version: "2.18.6"
	compileOnly group: "com.liferay", name: "jakarta.ws.rs", version: "3.1.0.LIFERAY-PATCHED-1"
	compileOnly group: "com.liferay.portal", name: "com.liferay.portal.kernel", version: "default"
	compileOnly group: "io.swagger.core.v3", name: "swagger-annotations-jakarta", version: "2.2.28"
	compileOnly group: "jakarta.annotation", name: "jakarta.annotation-api", version: "2.1.1"
	compileOnly group: "jakarta.servlet", name: "jakarta.servlet-api", version: "6.0.0"
	compileOnly group: "jakarta.validation", name: "jakarta.validation-api", version: "3.1.0"
	compileOnly group: "jakarta.xml.bind", name: "jakarta.xml.bind-api", version: "4.0.2"
	compileOnly group: "org.osgi", name: "org.osgi.annotation.versioning", version: "1.1.0"
	compileOnly project(":apps:portal-odata:portal-odata-api")
	compileOnly project(":apps:portal-vulcan:portal-vulcan-api")
	compileOnly project(":core:petra:petra-function")
	compileOnly project(":core:petra:petra-string")
}
```

- [ ] **Step 2: Author `portal-security-fips-rest-impl`**

`.lfrbuild-portal`: empty file.

`bnd.bnd`:

```
Bundle-Name: Liferay Crypto Health REST Implementation
Bundle-SymbolicName: com.liferay.portal.security.fips.rest.impl
Bundle-Version: 1.0.0
```

`build.gradle`:

```
dependencies {
	compileOnly group: "com.liferay", name: "jakarta.ws.rs", version: "3.1.0.LIFERAY-PATCHED-1"
	compileOnly group: "com.liferay.portal", name: "com.liferay.portal.kernel", version: "default"
	compileOnly group: "io.swagger.core.v3", name: "swagger-annotations-jakarta", version: "2.2.28"
	compileOnly group: "jakarta.annotation", name: "jakarta.annotation-api", version: "2.1.1"
	compileOnly group: "jakarta.servlet", name: "jakarta.servlet-api", version: "6.0.0"
	compileOnly group: "org.osgi", name: "org.osgi.service.component", version: "1.4.0"
	compileOnly group: "org.osgi", name: "org.osgi.service.component.annotations", version: "1.4.0"
	compileOnly group: "org.osgi", name: "osgi.core", version: "6.0.0"
	compileOnly project(":apps:portal-security:portal-security-fips-rest-api")
	compileOnly project(":apps:portal-odata:portal-odata-api")
	compileOnly project(":apps:portal-vulcan:portal-vulcan-api")
	compileOnly project(":core:petra:petra-function")
	testImplementation group: "org.mockito", name: "mockito-core", version: "5.4.0"
}
```

`rest-config.yaml`:

```yaml
apiDir: "../portal-security-fips-rest-api/src/main/java"
apiPackagePath: "com.liferay.portal.security.fips.rest"
application:
    baseURI: "/crypto-health"
    className: "CryptoHealthApplication"
    name: "Liferay.Crypto.Health.REST"
author: "Lucas Miranda"
clientDir: "../portal-security-fips-rest-client/src/main/java"
compatibilityVersion: 15
forcePredictableOperationId: true
javaEEPackage: "jakarta"
testDir: "../portal-security-fips-rest-test/src/testIntegration/java"
```

`rest-openapi.yaml`:

```yaml
components:
    schemas:
        HealthVerification:
            description: "Result of an on-demand cryptographic provider self-test re-verification."
            properties:
                date:
                    description: "When the verification ran."
                    format: "date-time"
                    type: "string"
                failedTest:
                    description: "The self-test that failed, if any."
                    type: "string"
                fipsState:
                    description: "The provider FIPS state at the time of failure."
                    type: "string"
                providerMessage:
                    description: "The provider exception message on failure."
                    type: "string"
                providerName:
                    description: "The active FIPS provider name."
                    type: "string"
                status:
                    description: "The verification outcome."
                    enum: ["HEALTHY", "FAILED", "NOT_APPLICABLE"]
                    type: "string"
            type: "object"
info:
    description: "Periodic cryptographic health verification."
    title: "Crypto Health"
    version: "v1.0"
openapi: "3.0.1"
paths:
    /health-verifications:
        post:
            description: "Forces the validated FIPS provider to re-run its self-tests on demand."
            operationId: "postHealthVerification"
            responses:
                200:
                    content:
                        application/json:
                            schema:
                                $ref: "#/components/schemas/HealthVerification"
                    description: ""
            tags: ["HealthVerification"]
tags:
    - name: "HealthVerification"
```

- [ ] **Step 3: Author `portal-security-fips-rest-client`**

`.lfrbuild-portal`: empty file.

`bnd.bnd`:

```
Bundle-Name: Liferay Crypto Health REST Client
Bundle-SymbolicName: com.liferay.portal.security.fips.rest.client
Bundle-Version: 1.0.0
Export-Package:\
	com.liferay.portal.security.fips.rest.client.dto.v1_0,\
	com.liferay.portal.security.fips.rest.client.function
```

`build.gradle`:

```
dependencies {
	compileOnly group: "jakarta.annotation", name: "jakarta.annotation-api", version: "2.1.1"
}
```

- [ ] **Step 4: Author `portal-security-fips-rest-test`**

`bnd.bnd`:

```
Bundle-Name: Liferay Crypto Health REST Test
Bundle-SymbolicName: com.liferay.portal.security.fips.rest.test
Bundle-Version: 1.0.0
```

`build.gradle`:

```
dependencies {
	testIntegrationImplementation group: "com.fasterxml.jackson.core", name: "jackson-databind", version: "2.18.6"
	testIntegrationImplementation group: "com.liferay", name: "jakarta.ws.rs", version: "3.1.0.LIFERAY-PATCHED-1"
	testIntegrationImplementation group: "jakarta.annotation", name: "jakarta.annotation-api", version: "2.1.1"
	testIntegrationImplementation project(":apps:portal-security:portal-security-fips-rest-api")
	testIntegrationImplementation project(":apps:portal-security:portal-security-fips-rest-client")
	testIntegrationImplementation project(":apps:portal-odata:portal-odata-api")
	testIntegrationImplementation project(":apps:portal-vulcan:portal-vulcan-api")
	testIntegrationImplementation project(":test:arquillian-extension-junit-bridge")
}
```

- [ ] **Step 5: Commit the hand-written files**

```bash
git add modules/apps/portal-security/portal-security-fips-rest-api \
        modules/apps/portal-security/portal-security-fips-rest-impl \
        modules/apps/portal-security/portal-security-fips-rest-client \
        modules/apps/portal-security/portal-security-fips-rest-test
git commit -m "LPD-97652 Add crypto health REST module scaffolding"
```

- [ ] **Step 6: Run REST Builder**

Run:

```bash
cd /home/me/dev/projects/liferay-portal/modules/apps/portal-security/portal-security-fips-rest-impl && ../../../../gradlew buildREST
```

Expected: generates `HealthVerification` DTO (api + client), `BaseHealthVerificationResourceImpl`, `CryptoHealthApplication`, OpenAPI resources under `-rest-impl/src/main/resources/OSGI-INF/`, and scaffolds `HealthVerificationResourceImpl.java`.

- [ ] **Step 7: Confirm the generated resource method signature**

Read `.../portal-security-fips-rest-impl/src/main/java/com/liferay/portal/security/fips/rest/internal/resource/v1_0/BaseHealthVerificationResourceImpl.java` and note the exact signature of the generated method (expected `public HealthVerification postHealthVerification() throws Exception`). Task 6 overrides exactly this signature.

- [ ] **Step 8: Commit the generated output**

```bash
git add modules/apps/portal-security/portal-security-fips-rest-api \
        modules/apps/portal-security/portal-security-fips-rest-client \
        modules/apps/portal-security/portal-security-fips-rest-impl
git commit -m "LPD-97652 Generate crypto health REST API, client, and base resource"
```

---

### Task 5: Crypto Officer role, resource action, and language key

Define the permission the endpoint checks and bootstrap the "Crypto Officer" role per company. This must exist before the resource impl (Task 6) references `FIPSActionKeys` and before the integration tests (Task 7).

**Files:**
- Create: `.../portal-security-fips-rest-impl/src/main/java/com/liferay/portal/security/fips/rest/internal/constants/FIPSActionKeys.java`
- Create: `.../portal-security-fips-rest-impl/src/main/resources/resource-actions/default.xml`
- Create: `.../portal-security-fips-rest-impl/src/main/resources/portlet.properties`
- Create: `.../portal-security-fips-rest-impl/src/main/java/com/liferay/portal/security/fips/rest/internal/instance/lifecycle/CryptoOfficerRolePortalInstanceLifecycleListener.java`
- Modify: `modules/apps/portal-language/portal-language-lang/src/main/resources/content/Language.properties`

**Interfaces:**
- Consumes: nothing from prior tasks.
- Produces: `FIPSActionKeys.TRIGGER_HEALTH_VERIFICATION` (`String` constant `"TRIGGER_HEALTH_VERIFICATION"`); the portal-scoped resource action; the bootstrapped `Crypto Officer` regular role holding that action at company scope.

- [ ] **Step 1: Create `FIPSActionKeys`**

```java
/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.constants;

/**
 * @author Lucas Miranda
 */
public class FIPSActionKeys {

	public static final String TRIGGER_HEALTH_VERIFICATION =
		"TRIGGER_HEALTH_VERIFICATION";

}
```

- [ ] **Step 2: Create `resource-actions/default.xml`**

Declares the action on the portal (company-wide) resource `90`:

```xml
<?xml version="1.0"?>
<!DOCTYPE resource-action-mapping PUBLIC "-//Liferay//DTD Resource Action Mapping 7.4.0//EN" "http://www.liferay.com/dtd/liferay-resource-action-mapping_7_4_0.dtd">

<resource-action-mapping>
	<portlet-resource>
		<portlet-name>90</portlet-name>
		<permissions>
			<supports>
				<action-key>TRIGGER_HEALTH_VERIFICATION</action-key>
			</supports>
			<site-member-defaults />
			<guest-defaults />
			<guest-unsupported>
				<action-key>TRIGGER_HEALTH_VERIFICATION</action-key>
			</guest-unsupported>
		</permissions>
	</portlet-resource>
</resource-action-mapping>
```

- [ ] **Step 3: Register the resource action**

Create `portlet.properties` in the impl module resources:

```properties
resource.actions.configs=resource-actions/default.xml
```

- [ ] **Step 4: Add the role name language key**

In the global `Language.properties`, insert in alphabetical position:

```properties
crypto-officer=Crypto Officer
```

- [ ] **Step 5: Create the role bootstrap listener**

```java
/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.instance.lifecycle;

import com.liferay.portal.instance.lifecycle.BasePortalInstanceLifecycleListener;
import com.liferay.portal.instance.lifecycle.PortalInstanceLifecycleListener;
import com.liferay.portal.kernel.language.Language;
import com.liferay.portal.kernel.model.Company;
import com.liferay.portal.kernel.model.ResourceConstants;
import com.liferay.portal.kernel.model.Role;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.model.role.RoleConstants;
import com.liferay.portal.kernel.service.ResourcePermissionLocalService;
import com.liferay.portal.kernel.service.RoleLocalService;
import com.liferay.portal.kernel.util.HashMapBuilder;
import com.liferay.portal.kernel.util.PortletKeys;
import com.liferay.portal.security.fips.rest.internal.constants.FIPSActionKeys;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * @author Lucas Miranda
 */
@Component(service = PortalInstanceLifecycleListener.class)
public class CryptoOfficerRolePortalInstanceLifecycleListener
	extends BasePortalInstanceLifecycleListener {

	@Override
	public void portalInstanceRegistered(Company company) throws Exception {
		long companyId = company.getCompanyId();

		Role role = _roleLocalService.fetchRole(companyId, _ROLE_NAME);

		if (role == null) {
			User guestUser = company.getGuestUser();

			role = _roleLocalService.addRole(
				null, guestUser.getUserId(), null, 0, _ROLE_NAME, null,
				HashMapBuilder.put(
					company.getLocale(),
					_language.get(company.getLocale(), "crypto-officer")
				).build(),
				RoleConstants.TYPE_REGULAR, null, null);
		}

		if (_resourcePermissionLocalService.fetchResourcePermission(
				companyId, PortletKeys.PORTAL, ResourceConstants.SCOPE_COMPANY,
				String.valueOf(companyId), role.getRoleId()) != null) {

			return;
		}

		_resourcePermissionLocalService.addResourcePermission(
			companyId, PortletKeys.PORTAL, ResourceConstants.SCOPE_COMPANY,
			String.valueOf(companyId), role.getRoleId(),
			FIPSActionKeys.TRIGGER_HEALTH_VERIFICATION);
	}

	private static final String _ROLE_NAME = "Crypto Officer";

	@Reference
	private Language _language;

	@Reference
	private ResourcePermissionLocalService _resourcePermissionLocalService;

	@Reference
	private RoleLocalService _roleLocalService;

}
```

- [ ] **Step 6: Regenerate language files**

Run:

```bash
cd /home/me/dev/projects/liferay-portal/modules/apps/portal-language/portal-language-lang && ../../../../gradlew buildLang
```

Expected: every `Language_<locale>.properties` regenerated with the new key.

- [ ] **Step 7: Verify the impl module compiles**

Run:

```bash
cd /home/me/dev/projects/liferay-portal/modules/apps/portal-security/portal-security-fips-rest-impl && ../../../../gradlew compileJava
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 8: Commit**

```bash
git add modules/apps/portal-security/portal-security-fips-rest-impl \
        modules/apps/portal-language/portal-language-lang/src/main/resources/content/Language.properties \
        modules/apps/portal-language/portal-language-lang/src/main/resources/content/Language_*.properties
git commit -m "LPD-97652 Add Crypto Officer role and health verification permission"
```

---

### Task 6: Resource implementation and audit emission

Implement the endpoint: permission check → `runSelfTests()` → on failure emit the `periodic-health-failure` audit event → map to the DTO and HTTP status (200/409/503). The audit-message construction is extracted into a pure, Mockito-unit-tested helper.

**Files:**
- Create: `.../portal-security-fips-rest-impl/src/main/java/com/liferay/portal/security/fips/rest/internal/audit/FIPSHealthAuditMessageBuilder.java`
- Modify (scaffolded in Task 4): `.../portal-security-fips-rest-impl/src/main/java/com/liferay/portal/security/fips/rest/internal/resource/v1_0/HealthVerificationResourceImpl.java`
- Test: `.../portal-security-fips-rest-impl/src/test/java/com/liferay/portal/security/fips/rest/internal/audit/FIPSHealthAuditMessageBuilderTest.java`

**Interfaces:**
- Consumes: `FIPSModeValidator.runSelfTests()` / `FIPSHealthCheckResult` (Tasks 1-3); `FIPSActionKeys` (Task 5); generated `HealthVerification` DTO + `BaseHealthVerificationResourceImpl` (Task 4).
- Produces: `FIPSHealthAuditMessageBuilder.build(long companyId, long userId, String userName, FIPSHealthCheckResult result, JSONFactory jsonFactory)` → `AuditMessage` (eventType `periodic-health-failure`).

- [ ] **Step 1: Write the failing unit test for the audit builder**

`FIPSHealthAuditMessageBuilderTest.java`:

```java
/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.audit;

import com.liferay.portal.kernel.audit.AuditMessage;
import com.liferay.portal.kernel.json.JSONFactory;
import com.liferay.portal.kernel.json.JSONObject;
import com.liferay.portal.kernel.security.fips.FIPSHealthCheckResult;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.mockito.Mockito;

/**
 * @author Lucas Miranda
 */
public class FIPSHealthAuditMessageBuilderTest {

	@Before
	public void setUp() {
		_jsonObject = Mockito.mock(JSONObject.class);

		Mockito.when(
			_jsonObject.put(Mockito.anyString(), Mockito.nullable(String.class))
		).thenReturn(
			_jsonObject
		);

		_jsonFactory = Mockito.mock(JSONFactory.class);

		Mockito.when(
			_jsonFactory.createJSONObject()
		).thenReturn(
			_jsonObject
		);
	}

	@Test
	public void testBuild() {
		FIPSHealthCheckResult result = FIPSHealthCheckResult.failed(
			"BCFIPS", "AES-KAT", "ERROR", "boom");

		AuditMessage auditMessage = FIPSHealthAuditMessageBuilder.build(
			123L, 456L, "Test User", result, _jsonFactory);

		Assert.assertEquals(
			"periodic-health-failure", auditMessage.getEventType());
		Assert.assertEquals(123L, auditMessage.getCompanyId());
		Assert.assertEquals(456L, auditMessage.getUserId());
		Assert.assertEquals(
			"com.liferay.portal.kernel.security.fips.FIPSModeValidator",
			auditMessage.getClassName());

		Mockito.verify(_jsonObject).put("severity", "CRITICAL");
		Mockito.verify(_jsonObject).put("failedTest", "AES-KAT");
		Mockito.verify(_jsonObject).put("fipsState", "ERROR");
		Mockito.verify(_jsonObject).put("providerMessage", "boom");
		Mockito.verify(_jsonObject).put("providerName", "BCFIPS");
	}

	private JSONFactory _jsonFactory;
	private JSONObject _jsonObject;

}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
cd /home/me/dev/projects/liferay-portal/modules/apps/portal-security/portal-security-fips-rest-impl && ../../../../gradlew test --tests FIPSHealthAuditMessageBuilderTest
```

Expected: FAIL — `FIPSHealthAuditMessageBuilder` does not exist.

- [ ] **Step 3: Implement `FIPSHealthAuditMessageBuilder`**

```java
/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.audit;

import com.liferay.portal.kernel.audit.AuditMessage;
import com.liferay.portal.kernel.json.JSONFactory;
import com.liferay.portal.kernel.json.JSONObject;
import com.liferay.portal.kernel.security.fips.FIPSHealthCheckResult;
import com.liferay.portal.kernel.security.fips.FIPSModeValidator;

/**
 * @author Lucas Miranda
 */
public class FIPSHealthAuditMessageBuilder {

	public static AuditMessage build(
		long companyId, long userId, String userName,
		FIPSHealthCheckResult result, JSONFactory jsonFactory) {

		JSONObject additionalInfoJSONObject = jsonFactory.createJSONObject();

		additionalInfoJSONObject.put(
			"severity", "CRITICAL"
		).put(
			"failedTest", result.getFailedTest()
		).put(
			"fipsState", result.getFipsState()
		).put(
			"providerMessage", result.getProviderMessage()
		).put(
			"providerName", result.getProviderName()
		);

		return new AuditMessage(
			companyId, userId, userName, additionalInfoJSONObject,
			FIPSModeValidator.class.getName(), "0", _EVENT_TYPE, null);
	}

	private static final String _EVENT_TYPE = "periodic-health-failure";

}
```

- [ ] **Step 4: Run the test to verify it passes**

Run:

```bash
cd /home/me/dev/projects/liferay-portal/modules/apps/portal-security/portal-security-fips-rest-impl && ../../../../gradlew test --tests FIPSHealthAuditMessageBuilderTest
```

Expected: PASS.

- [ ] **Step 5: Implement `HealthVerificationResourceImpl`**

Replace the scaffolded override. Confirm the method signature against the generated base from Task 4 Step 7 before writing:

```java
/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.resource.v1_0;

import com.liferay.portal.kernel.audit.AuditException;
import com.liferay.portal.kernel.audit.AuditMessage;
import com.liferay.portal.kernel.audit.AuditRouter;
import com.liferay.portal.kernel.json.JSONFactory;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.security.auth.PrincipalException;
import com.liferay.portal.kernel.security.fips.FIPSHealthCheckResult;
import com.liferay.portal.kernel.security.fips.FIPSModeValidator;
import com.liferay.portal.kernel.security.permission.PermissionChecker;
import com.liferay.portal.kernel.security.permission.PermissionThreadLocal;
import com.liferay.portal.kernel.service.permission.PortalPermissionUtil;
import com.liferay.portal.security.fips.rest.dto.v1_0.HealthVerification;
import com.liferay.portal.security.fips.rest.internal.audit.FIPSHealthAuditMessageBuilder;
import com.liferay.portal.security.fips.rest.internal.constants.FIPSActionKeys;
import com.liferay.portal.security.fips.rest.resource.v1_0.HealthVerificationResource;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import java.util.Date;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * @author Lucas Miranda
 */
@Component(
	properties = "OSGI-INF/liferay/rest/v1_0/health-verification.properties",
	scope = ServiceScope.PROTOTYPE, service = HealthVerificationResource.class
)
public class HealthVerificationResourceImpl
	extends BaseHealthVerificationResourceImpl {

	@Override
	public HealthVerification postHealthVerification() throws Exception {
		PermissionChecker permissionChecker =
			PermissionThreadLocal.getPermissionChecker();

		if (!PortalPermissionUtil.contains(
				permissionChecker,
				FIPSActionKeys.TRIGGER_HEALTH_VERIFICATION)) {

			throw new PrincipalException.MustHavePermission(
				permissionChecker,
				FIPSActionKeys.TRIGGER_HEALTH_VERIFICATION);
		}

		FIPSHealthCheckResult result = FIPSModeValidator.runSelfTests();

		HealthVerification healthVerification = _toHealthVerification(result);

		if (result.getStatus() == FIPSHealthCheckResult.Status.NOT_APPLICABLE) {
			throw new WebApplicationException(
				Response.status(
					Response.Status.CONFLICT
				).entity(
					healthVerification
				).build());
		}

		if (result.getStatus() == FIPSHealthCheckResult.Status.FAILED) {
			_routeAuditMessage(result);

			throw new WebApplicationException(
				Response.status(
					Response.Status.SERVICE_UNAVAILABLE
				).entity(
					healthVerification
				).build());
		}

		return healthVerification;
	}

	private void _routeAuditMessage(FIPSHealthCheckResult result) {
		try {
			AuditMessage auditMessage = FIPSHealthAuditMessageBuilder.build(
				contextCompany.getCompanyId(), contextUser.getUserId(),
				contextUser.getFullName(), result, _jsonFactory);

			_auditRouter.route(auditMessage);
		}
		catch (AuditException auditException) {
			_log.error(
				"Unable to route periodic-health-failure audit message",
				auditException);
		}
	}

	private HealthVerification _toHealthVerification(
		FIPSHealthCheckResult result) {

		HealthVerification healthVerification = new HealthVerification();

		healthVerification.setDate(new Date());
		healthVerification.setFailedTest(result.getFailedTest());
		healthVerification.setFipsState(result.getFipsState());
		healthVerification.setProviderMessage(result.getProviderMessage());
		healthVerification.setProviderName(result.getProviderName());
		healthVerification.setStatus(
			HealthVerification.Status.create(result.getStatus().name()));

		return healthVerification;
	}

	private static final Log _log = LogFactoryUtil.getLog(
		HealthVerificationResourceImpl.class);

	@Reference
	private AuditRouter _auditRouter;

	@Reference
	private JSONFactory _jsonFactory;

}
```

> NOTE on `import ...ServiceScope`: use the same `@Component` annotation shape the generated scaffold already produced (Task 4 emits a `HealthVerificationResourceImpl` scaffold with the correct `@Component` block and `ServiceScope` import). Keep the scaffold's `@Component` and imports; add only the method body and the two `@Reference` fields. `contextCompany` and `contextUser` are inherited `protected` fields from `BaseHealthVerificationResourceImpl`.
>
> NOTE on `HealthVerification.Status`: REST Builder generates a nested `Status` enum for an enum-typed property, with a `create(String)` factory. If the generated DTO models `status` as a plain `String` instead (verify against the generated `HealthVerification.java`), replace `setStatus(HealthVerification.Status.create(...))` with `setStatus(result.getStatus().name())`.

- [ ] **Step 6: Verify the module compiles and the unit test still passes**

Run:

```bash
cd /home/me/dev/projects/liferay-portal/modules/apps/portal-security/portal-security-fips-rest-impl && ../../../../gradlew test --tests FIPSHealthAuditMessageBuilderTest
```

Expected: BUILD SUCCESSFUL, test PASS.

- [ ] **Step 7: Commit**

```bash
git add modules/apps/portal-security/portal-security-fips-rest-impl
git commit -m "LPD-97652 Implement crypto health verification endpoint"
```

---

### Task 7: Integration tests for auth wiring

Verify the endpoint's authorization on a normal (non-FIPS) bundle: an unauthorized caller is rejected, and an authorized caller against a FIPS-disabled instance gets the `NOT_APPLICABLE`/409 branch. This exercises REST wiring + role bootstrap + permission check + the 409 path without a FIPS provider (the genuine KAT re-run is Layer B, deferred).

**Files:**
- Create: `.../portal-security-fips-rest-test/src/testIntegration/java/com/liferay/portal/security/fips/rest/resource/v1_0/test/HealthVerificationResourceTest.java`

**Interfaces:**
- Consumes: generated client + `HealthVerification` DTO (Task 4); the Crypto Officer role/action (Task 5); the deployed endpoint (Task 6).
- Produces: nothing (terminal verification task).

- [ ] **Step 1: Deploy the module cluster to the running bundle**

Run:

```bash
cd /home/me/dev/projects/liferay-portal/modules/apps/portal-security/portal-security-fips-rest-api && ../../../../gradlew deploy
cd /home/me/dev/projects/liferay-portal/modules/apps/portal-security/portal-security-fips-rest-impl && ../../../../gradlew deploy
cd /home/me/dev/projects/liferay-portal/modules/apps/portal-security/portal-security-fips-rest-client && ../../../../gradlew deploy
```

(The `-rest-test` module is NOT deployed — `testIntegration` wires it in.)

- [ ] **Step 2: Write the integration test**

```java
/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.resource.v1_0.test;

import com.liferay.arquillian.extension.junit.bridge.junit.Arquillian;
import com.liferay.portal.kernel.model.Role;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.model.role.RoleConstants;
import com.liferay.portal.kernel.service.RoleLocalServiceUtil;
import com.liferay.portal.kernel.test.rule.AggregateTestRule;
import com.liferay.portal.kernel.test.util.TestPropsValues;
import com.liferay.portal.kernel.test.util.UserTestUtil;
import com.liferay.portal.test.rule.LiferayIntegrationTestRule;

import java.net.HttpURLConnection;
import java.net.URL;

import java.util.Base64;

import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * @author Lucas Miranda
 */
@RunWith(Arquillian.class)
public class HealthVerificationResourceTest {

	@ClassRule
	@Rule
	public static final AggregateTestRule aggregateTestRule =
		new LiferayIntegrationTestRule();

	@Before
	public void setUp() throws Exception {
		_companyId = TestPropsValues.getCompanyId();
	}

	@Test
	public void testAuthorizedCallerOnNonFIPSInstanceGets409()
		throws Exception {

		User user = UserTestUtil.addUser();

		Role role = RoleLocalServiceUtil.getRole(_companyId, "Crypto Officer");

		RoleLocalServiceUtil.addUserRole(user.getUserId(), role.getRoleId());

		int responseCode = _invoke(user.getEmailAddress(), "test");

		// FIPS is disabled on a normal bundle, so the endpoint reports
		// NOT_APPLICABLE as HTTP 409.

		Assert.assertEquals(HttpURLConnection.HTTP_CONFLICT, responseCode);
	}

	@Test
	public void testUnauthorizedCallerGets403() throws Exception {
		User user = UserTestUtil.addUser();

		int responseCode = _invoke(user.getEmailAddress(), "test");

		Assert.assertEquals(HttpURLConnection.HTTP_FORBIDDEN, responseCode);
	}

	private int _invoke(String emailAddress, String password)
		throws Exception {

		URL url = new URL(
			"http://localhost:8080/o/crypto-health/v1.0/health-verifications");

		HttpURLConnection httpURLConnection =
			(HttpURLConnection)url.openConnection();

		httpURLConnection.setRequestMethod("POST");

		String encodedCredentials = Base64.getEncoder().encodeToString(
			(emailAddress + ":" + password).getBytes());

		httpURLConnection.setRequestProperty(
			"Authorization", "Basic " + encodedCredentials);

		return httpURLConnection.getResponseCode();
	}

	private long _companyId;

}
```

> NOTE: `UserTestUtil.addUser()` creates a user with the default test password `test`. If the bundle's HTTP port differs from `8080`, resolve it from `<tomcat>/conf/server.xml` per `.claude/rules/tomcat.md` and update the URL. Prefer the generated `HealthVerificationResource` client builder if the surrounding test suite uses that pattern; the raw `HttpURLConnection` above keeps the auth assertions explicit and dependency-light.

- [ ] **Step 3: Run the integration test**

Run:

```bash
cd /home/me/dev/projects/liferay-portal/modules/apps/portal-security/portal-security-fips-rest-test && ../../../../gradlew testIntegration --tests HealthVerificationResourceTest
```

Expected: PASS (2 tests) — 403 for the unauthorized user, 409 for the Crypto Officer on the non-FIPS instance.

- [ ] **Step 4: Commit**

```bash
git add modules/apps/portal-security/portal-security-fips-rest-test
git commit -m "LPD-97652 Add integration tests for crypto health endpoint auth"
```

---

## Deferred / Out of Scope (record on the ticket)

- **Layer B — real FIPS verification.** The genuine BCFIPS `runSelfTests` symbol, real approved-mode, and induced-failure → Error State → 503 + audit event can only run on a FIPS-booted JVM (LPD-80674, still Open). Until then the reflective executor (Task 3) is code-reviewed and compiles but is unverified against a live provider.
- **External scheduler wiring** is admin configuration, not code: register an OAuth2 application (Headless Server profile, `client_credentials` grant) whose `clientCredentialUserId` is a service-account user granted the Crypto Officer role, and grant that app the `Liferay.Crypto.Health.REST` OAuth2 scope. The single `PortalPermissionUtil.contains(...)` check then authorizes both the human and the scheduler.
- **Automatic/scheduled invocation** — the endpoint is on-demand only; scheduling is the external caller's responsibility.
- **Error State recovery** — restart-only by design; no reset endpoint.