/**
 * SPDX-FileCopyrightText: (c) 2000 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.multi.factor.authentication.email.otp.web.internal.checker;

import com.liferay.multi.factor.authentication.email.otp.web.internal.constants.MFAEmailOTPWebKeys;
import com.liferay.portal.kernel.module.util.SystemBundleUtil;
import com.liferay.portal.kernel.test.ReflectionTestUtil;
import com.liferay.portal.test.rule.LiferayUnitTestRule;

import jakarta.servlet.http.HttpSession;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.mockito.MockedStatic;
import org.mockito.Mockito;

import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;

/**
 * @author Stian Sigvartsen
 */
public class EmailOTPBrowserMFACheckerTest {

	@ClassRule
	@Rule
	public static final LiferayUnitTestRule liferayUnitTestRule =
		LiferayUnitTestRule.INSTANCE;

	@BeforeClass
	public static void setUpClass() {
		BundleContext bundleContext = SystemBundleUtil.getBundleContext();

		Mockito.when(
			FrameworkUtil.getBundle(Mockito.any())
		).thenReturn(
			bundleContext.getBundle()
		);
	}

	@AfterClass
	public static void tearDownClass() {
		_frameworkUtilMockedStatic.close();
	}

	@Test
	public void testObfuscateEmailAddress() throws Exception {
		Assert.assertEquals(
			"*@liferay.com",
			EmailOTPBrowserMFAChecker.obfuscateEmailAddress("t@liferay.com"));
		Assert.assertEquals(
			"**@liferay.com",
			EmailOTPBrowserMFAChecker.obfuscateEmailAddress("te@liferay.com"));
		Assert.assertEquals(
			"***@liferay.com",
			EmailOTPBrowserMFAChecker.obfuscateEmailAddress("tes@liferay.com"));
		Assert.assertEquals(
			"t***@liferay.com",
			EmailOTPBrowserMFAChecker.obfuscateEmailAddress(
				"test@liferay.com"));
		Assert.assertEquals(
			"t***1@liferay.com",
			EmailOTPBrowserMFAChecker.obfuscateEmailAddress(
				"test1@liferay.com"));
		Assert.assertEquals(
			"te***1@liferay.com",
			EmailOTPBrowserMFAChecker.obfuscateEmailAddress(
				"test11@liferay.com"));
	}

	@Test
	public void testVerify() throws Exception {
		EmailOTPBrowserMFAChecker emailOTPBrowserMFAChecker =
			new EmailOTPBrowserMFAChecker();

		// A session that holds no one-time password must not verify

		Assert.assertFalse(_verify(emailOTPBrowserMFAChecker, null, "123456"));

		// A submitted value of null must not verify

		Assert.assertFalse(_verify(emailOTPBrowserMFAChecker, "123456", null));

		// A value sharing every character but the last must not verify

		Assert.assertFalse(
			_verify(emailOTPBrowserMFAChecker, "123456", "123457"));

		// A longer value sharing the whole prefix must not verify

		Assert.assertFalse(
			_verify(emailOTPBrowserMFAChecker, "123456", "1234560"));

		// A matching value must verify

		Assert.assertTrue(
			_verify(emailOTPBrowserMFAChecker, "123456", "123456"));
	}

	private boolean _verify(
		EmailOTPBrowserMFAChecker emailOTPBrowserMFAChecker,
		String expectedMFAEmailOTP, String otp) {

		HttpSession httpSession = Mockito.mock(HttpSession.class);

		Mockito.when(
			httpSession.getAttribute(MFAEmailOTPWebKeys.MFA_EMAIL_OTP)
		).thenReturn(
			expectedMFAEmailOTP
		);

		return ReflectionTestUtil.invoke(
			emailOTPBrowserMFAChecker, "_verify",
			new Class<?>[] {HttpSession.class, String.class}, httpSession, otp);
	}

	private static final MockedStatic<FrameworkUtil>
		_frameworkUtilMockedStatic = Mockito.mockStatic(FrameworkUtil.class);

}