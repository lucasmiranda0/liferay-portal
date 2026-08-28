/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.login.authentication.facebook.connect.web.internal.struts;

import com.liferay.portal.kernel.facebook.FacebookConnect;
import com.liferay.portal.kernel.json.JSONFactory;
import com.liferay.portal.kernel.json.JSONObject;
import com.liferay.portal.kernel.security.auth.PrincipalException;
import com.liferay.portal.kernel.test.ReflectionTestUtil;
import com.liferay.portal.kernel.test.util.RandomTestUtil;
import com.liferay.portal.kernel.theme.ThemeDisplay;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.WebKeys;
import com.liferay.portal.test.rule.LiferayUnitTestRule;

import jakarta.servlet.http.HttpSession;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.mockito.Mockito;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * @author Lucas Miranda
 */
public class FacebookConnectStrutsActionTest {

	@ClassRule
	@Rule
	public static final LiferayUnitTestRule liferayUnitTestRule =
		LiferayUnitTestRule.INSTANCE;

	@Test
	public void testExecute() throws Exception {
		String nonce = RandomTestUtil.randomString();

		Assert.assertEquals(_FORWARD, _execute(nonce, nonce));

		Assert.assertThrows(
			PrincipalException.MustHaveValidCSRFToken.class,
			() -> _execute(null, nonce));
		Assert.assertThrows(
			PrincipalException.MustHaveValidCSRFToken.class,
			() -> _execute(nonce, RandomTestUtil.randomString()));
	}

	private String _execute(String nonce, String stateNonce) throws Exception {
		MockHttpServletRequest mockHttpServletRequest =
			new MockHttpServletRequest();

		mockHttpServletRequest.setAttribute(
			WebKeys.THEME_DISPLAY, Mockito.mock(ThemeDisplay.class));

		FacebookConnect facebookConnect = Mockito.mock(FacebookConnect.class);

		Mockito.when(
			facebookConnect.isEnabled(Mockito.anyLong())
		).thenReturn(
			true
		);

		HttpSession httpSession = mockHttpServletRequest.getSession();

		httpSession.setAttribute(WebKeys.FACEBOOK_NONCE, nonce);

		String state = RandomTestUtil.randomString();

		mockHttpServletRequest.addParameter("state", state);

		JSONFactory jsonFactory = Mockito.mock(JSONFactory.class);

		JSONObject jsonObject = Mockito.mock(JSONObject.class);

		Mockito.when(
			jsonObject.getString("stateNonce")
		).thenReturn(
			stateNonce
		);

		Mockito.when(
			jsonFactory.createJSONObject(state)
		).thenReturn(
			jsonObject
		);

		FacebookConnectStrutsAction facebookConnectStrutsAction =
			new FacebookConnectStrutsAction();

		ReflectionTestUtil.setFieldValue(
			facebookConnectStrutsAction, "_facebookConnect", facebookConnect);
		ReflectionTestUtil.setFieldValue(
			facebookConnectStrutsAction, "_forward", _FORWARD);
		ReflectionTestUtil.setFieldValue(
			facebookConnectStrutsAction, "_jsonFactory", jsonFactory);
		ReflectionTestUtil.setFieldValue(
			facebookConnectStrutsAction, "_portal", Mockito.mock(Portal.class));

		return facebookConnectStrutsAction.execute(
			mockHttpServletRequest, new MockHttpServletResponse());
	}

	private static final String _FORWARD = RandomTestUtil.randomString();

}