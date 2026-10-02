/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.iframe.web.internal.display.context;

import com.liferay.iframe.web.internal.configuration.IFramePortletInstanceConfiguration;
import com.liferay.portal.configuration.module.configuration.ConfigurationProviderUtil;
import com.liferay.portal.kernel.module.service.Snapshot;
import com.liferay.portal.kernel.test.ReflectionTestUtil;
import com.liferay.portal.kernel.test.util.RandomTestUtil;
import com.liferay.portal.kernel.theme.ThemeDisplay;
import com.liferay.portal.kernel.util.WebKeys;
import com.liferay.portal.security.key.KeyReference;
import com.liferay.portal.security.key.KeyReferenceUtil;
import com.liferay.portal.security.key.secret.SecretResolver;
import com.liferay.portal.security.key.secret.SecretResolverUtil;
import com.liferay.portal.test.rule.LiferayUnitTestRule;

import jakarta.portlet.PortletRequest;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * @author Lucas Miranda
 */
public class IFrameDisplayContextTest {

	@ClassRule
	@Rule
	public static final LiferayUnitTestRule liferayUnitTestRule =
		LiferayUnitTestRule.INSTANCE;

	@Before
	public void setUp() {
		_secretResolverSnapshot = ReflectionTestUtil.getAndSetFieldValue(
			SecretResolverUtil.class, "_secretResolverSnapshot",
			new Snapshot<SecretResolver>(
				SecretResolverUtil.class, SecretResolver.class) {

				@Override
				public SecretResolver get() {
					return _secretResolver;
				}

			});
	}

	@After
	public void tearDown() {
		ReflectionTestUtil.setFieldValue(
			SecretResolverUtil.class, "_secretResolverSnapshot",
			_secretResolverSnapshot);
	}

	@Test
	public void testGetBasicPassword() throws Exception {
		long companyId = RandomTestUtil.randomLong();
		String keyReferenceString = KeyReferenceUtil.toKeyReferenceString(
			new KeyReference(
				RandomTestUtil.randomString(), RandomTestUtil.randomString(),
				KeyReference.Type.SECRET));
		String password =
			RandomTestUtil.randomString() + "=" + RandomTestUtil.randomString();

		_secretResolver = Mockito.mock(SecretResolver.class);

		Mockito.when(
			_secretResolver.resolve(companyId, keyReferenceString)
		).thenReturn(
			password
		);

		_testGetBasicPassword(companyId, password, keyReferenceString);
		_testGetBasicPassword(companyId, password, password);
	}

	private void _testGetBasicPassword(
			long companyId, String expectedBasicPassword, String basicPassword)
		throws Exception {

		IFramePortletInstanceConfiguration iFramePortletInstanceConfiguration =
			Mockito.mock(IFramePortletInstanceConfiguration.class);

		Mockito.when(
			iFramePortletInstanceConfiguration.basicPassword()
		).thenReturn(
			basicPassword
		);

		ThemeDisplay themeDisplay = Mockito.mock(ThemeDisplay.class);

		Mockito.when(
			themeDisplay.getCompanyId()
		).thenReturn(
			companyId
		);

		PortletRequest portletRequest = Mockito.mock(PortletRequest.class);

		Mockito.when(
			portletRequest.getAttribute(WebKeys.THEME_DISPLAY)
		).thenReturn(
			themeDisplay
		);

		try (MockedStatic<ConfigurationProviderUtil>
				configurationProviderUtilMockedStatic = Mockito.mockStatic(
					ConfigurationProviderUtil.class)) {

			configurationProviderUtilMockedStatic.when(
				() -> ConfigurationProviderUtil.getPortletInstanceConfiguration(
					IFramePortletInstanceConfiguration.class, themeDisplay)
			).thenReturn(
				iFramePortletInstanceConfiguration
			);

			IFrameDisplayContext iFrameDisplayContext =
				new IFrameDisplayContext(portletRequest);

			Assert.assertEquals(
				expectedBasicPassword, iFrameDisplayContext.getBasicPassword());
		}
	}

	private SecretResolver _secretResolver;
	private Snapshot<SecretResolver> _secretResolverSnapshot;

}