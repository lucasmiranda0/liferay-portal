/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.sharepoint.rest.repository.internal.document.library.repository.authorization.oauth2;

import com.liferay.document.library.repository.authorization.oauth2.OAuth2AuthorizationException;
import com.liferay.portal.kernel.test.util.RandomTestUtil;
import com.liferay.portal.test.rule.LiferayUnitTestRule;

import java.lang.reflect.Constructor;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

/**
 * @author Lucas Miranda
 */
public class SharepointRepositoryRequestStateTest {

	@ClassRule
	@Rule
	public static final LiferayUnitTestRule liferayUnitTestRule =
		LiferayUnitTestRule.INSTANCE;

	@Test
	public void testValidateNonce() throws Exception {
		SharepointRepositoryRequestState sharepointRepositoryRequestState =
			_create();

		sharepointRepositoryRequestState.validateNonce(_NONCE);

		Assert.assertThrows(
			OAuth2AuthorizationException.InvalidNonce.class,
			() -> sharepointRepositoryRequestState.validateNonce(null));

		OAuth2AuthorizationException.InvalidNonce invalidNonce =
			Assert.assertThrows(
				OAuth2AuthorizationException.InvalidNonce.class,
				() -> sharepointRepositoryRequestState.validateNonce(
					RandomTestUtil.randomString()));

		String message = invalidNonce.getMessage();

		Assert.assertFalse(message.contains(_NONCE));
	}

	@Test
	public void testValidateState() throws Exception {
		SharepointRepositoryRequestState sharepointRepositoryRequestState =
			_create();

		sharepointRepositoryRequestState.validateState(_STATE);

		Assert.assertThrows(
			OAuth2AuthorizationException.InvalidState.class,
			() -> sharepointRepositoryRequestState.validateState(null));

		OAuth2AuthorizationException.InvalidState invalidState =
			Assert.assertThrows(
				OAuth2AuthorizationException.InvalidState.class,
				() -> sharepointRepositoryRequestState.validateState(
					RandomTestUtil.randomString()));

		String message = invalidState.getMessage();

		Assert.assertFalse(message.contains(_STATE));
	}

	private SharepointRepositoryRequestState _create() throws Exception {
		Constructor<SharepointRepositoryRequestState> constructor =
			SharepointRepositoryRequestState.class.getDeclaredConstructor(
				long.class, String.class, String.class, String.class);

		constructor.setAccessible(true);

		return constructor.newInstance(
			RandomTestUtil.randomLong(), _NONCE, _STATE,
			RandomTestUtil.randomString());
	}

	private static final String _NONCE = RandomTestUtil.randomString();

	private static final String _STATE = RandomTestUtil.randomString();

}