/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.sharepoint.rest.repository.internal.document.library.repository.authorization.oauth2;

import com.liferay.document.library.repository.authorization.oauth2.OAuth2AuthorizationException;
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

		// A value sharing every character but the last must not validate

		Assert.assertNotNull(
			_getInvalidNonce(sharepointRepositoryRequestState, "aBcDeF13"));

		// A longer value sharing the whole prefix must not validate

		Assert.assertNotNull(
			_getInvalidNonce(sharepointRepositoryRequestState, _NONCE + "0"));

		// A value of null must not validate

		Assert.assertNotNull(
			_getInvalidNonce(sharepointRepositoryRequestState, null));

		// The message must not carry the expected nonce

		OAuth2AuthorizationException.InvalidNonce invalidNonce =
			_getInvalidNonce(sharepointRepositoryRequestState, "aBcDeF13");

		String message = invalidNonce.getMessage();

		Assert.assertFalse(message.contains(_NONCE));
	}

	@Test
	public void testValidateState() throws Exception {
		SharepointRepositoryRequestState sharepointRepositoryRequestState =
			_create();

		sharepointRepositoryRequestState.validateState(_STATE);

		// A value sharing every character but the last must not validate

		Assert.assertNotNull(
			_getInvalidState(sharepointRepositoryRequestState, "gHiJkL35"));

		// A value of null must not validate

		Assert.assertNotNull(
			_getInvalidState(sharepointRepositoryRequestState, null));

		// The message must not carry the expected state

		OAuth2AuthorizationException.InvalidState invalidState =
			_getInvalidState(sharepointRepositoryRequestState, "gHiJkL35");

		String message = invalidState.getMessage();

		Assert.assertFalse(message.contains(_STATE));
	}

	private SharepointRepositoryRequestState _create() throws Exception {
		Constructor<SharepointRepositoryRequestState> constructor =
			SharepointRepositoryRequestState.class.getDeclaredConstructor(
				long.class, String.class, String.class, String.class);

		constructor.setAccessible(true);

		return constructor.newInstance(0L, _NONCE, _STATE, "http://localhost");
	}

	private OAuth2AuthorizationException.InvalidNonce _getInvalidNonce(
		SharepointRepositoryRequestState sharepointRepositoryRequestState,
		String nonce) {

		try {
			sharepointRepositoryRequestState.validateNonce(nonce);
		}
		catch (OAuth2AuthorizationException.InvalidNonce
					oAuth2AuthorizationException) {

			return oAuth2AuthorizationException;
		}
		catch (Exception exception) {
			throw new AssertionError(exception);
		}

		throw new AssertionError();
	}

	private OAuth2AuthorizationException.InvalidState _getInvalidState(
		SharepointRepositoryRequestState sharepointRepositoryRequestState,
		String state) {

		try {
			sharepointRepositoryRequestState.validateState(state);
		}
		catch (OAuth2AuthorizationException.InvalidState
					oAuth2AuthorizationException) {

			return oAuth2AuthorizationException;
		}
		catch (Exception exception) {
			throw new AssertionError(exception);
		}

		throw new AssertionError();
	}

	private static final String _NONCE = "aBcDeF12";

	private static final String _STATE = "gHiJkL34";

}