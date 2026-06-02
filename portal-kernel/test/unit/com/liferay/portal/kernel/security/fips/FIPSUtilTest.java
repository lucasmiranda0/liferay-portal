/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.security.fips;

import com.liferay.portal.kernel.test.ReflectionTestUtil;
import com.liferay.portal.kernel.test.rule.CodeCoverageAssertor;
import com.liferay.portal.kernel.util.PropsValues;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

/**
 * @author Lucas Miranda
 */
public class FIPSUtilTest {

	@ClassRule
	@Rule
	public static final CodeCoverageAssertor codeCoverageAssertor =
		CodeCoverageAssertor.INSTANCE;

	@Before
	public void setUp() {
		_fipsEnabled = PropsValues.FIPS_ENABLED;
	}

	@After
	public void tearDown() {
		_setFIPSEnabled(_fipsEnabled);
	}

	@Test
	public void testCheckCipherAlgorithmApprovedWhenEnabled() {
		_setFIPSEnabled(true);

		Assert.assertEquals("AES", FIPSUtil.checkCipherAlgorithm("AES"));
		Assert.assertEquals(
			FIPSUtil.GCM_TRANSFORMATION,
			FIPSUtil.checkCipherAlgorithm(FIPSUtil.GCM_TRANSFORMATION));
	}

	@Test
	public void testCheckCipherAlgorithmPassThroughWhenDisabled() {
		_setFIPSEnabled(false);

		Assert.assertEquals(
			"Blowfish", FIPSUtil.checkCipherAlgorithm("Blowfish"));
	}

	@Test(expected = SecurityException.class)
	public void testCheckCipherAlgorithmRejectedWhenEnabled() {
		_setFIPSEnabled(true);

		FIPSUtil.checkCipherAlgorithm("Blowfish");
	}

	@Test(expected = SecurityException.class)
	public void testCheckCipherAlgorithmRejectsNullWhenEnabled() {
		_setFIPSEnabled(true);

		FIPSUtil.checkCipherAlgorithm(null);
	}

	@Test
	public void testCheckDigestAlgorithmApprovedWhenEnabled() {
		_setFIPSEnabled(true);

		Assert.assertEquals(
			"SHA-256", FIPSUtil.checkDigestAlgorithm("SHA-256"));
		Assert.assertEquals("SHA256", FIPSUtil.checkDigestAlgorithm("SHA256"));
		Assert.assertEquals(
			"SHA-512", FIPSUtil.checkDigestAlgorithm("SHA-512"));
	}

	@Test
	public void testCheckDigestAlgorithmPassThroughWhenDisabled() {
		_setFIPSEnabled(false);

		Assert.assertEquals("MD5", FIPSUtil.checkDigestAlgorithm("MD5"));
	}

	@Test(expected = SecurityException.class)
	public void testCheckDigestAlgorithmRejectsMD5WhenEnabled() {
		_setFIPSEnabled(true);

		FIPSUtil.checkDigestAlgorithm("MD5");
	}

	@Test(expected = SecurityException.class)
	public void testCheckDigestAlgorithmRejectsNullWhenEnabled() {
		_setFIPSEnabled(true);

		FIPSUtil.checkDigestAlgorithm(null);
	}

	@Test(expected = SecurityException.class)
	public void testCheckDigestAlgorithmRejectsSHA1WhenEnabled() {
		_setFIPSEnabled(true);

		FIPSUtil.checkDigestAlgorithm("SHA-1");
	}

	@Test
	public void testCheckKeySizeApprovedWhenEnabled() {
		_setFIPSEnabled(true);

		FIPSUtil.checkKeySize("AES", 128);
		FIPSUtil.checkKeySize("AES", 192);
		FIPSUtil.checkKeySize("AES", 256);
	}

	@Test
	public void testCheckKeySizePassThroughWhenDisabled() {
		_setFIPSEnabled(false);

		FIPSUtil.checkKeySize("AES", 56);
	}

	@Test(expected = SecurityException.class)
	public void testCheckKeySizeRejectedWhenEnabled() {
		_setFIPSEnabled(true);

		FIPSUtil.checkKeySize("AES", 56);
	}

	@Test
	public void testConstructor() {
		new FIPSUtil();
	}

	@Test
	public void testIsEnabled() {
		_setFIPSEnabled(true);

		Assert.assertTrue(FIPSUtil.isEnabled());

		_setFIPSEnabled(false);

		Assert.assertFalse(FIPSUtil.isEnabled());
	}

	private void _setFIPSEnabled(boolean fipsEnabled) {
		ReflectionTestUtil.setFieldValue(
			PropsValues.class, "FIPS_ENABLED", fipsEnabled);
	}

	private boolean _fipsEnabled;

}