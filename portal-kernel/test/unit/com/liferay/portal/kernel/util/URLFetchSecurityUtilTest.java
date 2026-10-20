/**
 * SPDX-FileCopyrightText: (c) 2000 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.util;

import com.liferay.petra.function.UnsafeFunction;

import java.net.InetAddress;
import java.net.UnknownHostException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * @author Lucas Miranda
 */
public class URLFetchSecurityUtilTest {

	@BeforeClass
	public static void setUpClass() throws Exception {
		_propsUtilMockedStatic.when(
			() -> PropsUtil.get(PropsKeys.DNS_SECURITY_ADDRESS_TIMEOUT_SECONDS)
		).thenReturn(
			String.valueOf(2)
		);

		_propsUtilMockedStatic.when(
			() -> PropsUtil.get(PropsKeys.DNS_SECURITY_THREAD_LIMIT)
		).thenReturn(
			String.valueOf(10)
		);

		_propsUtilMockedStatic.when(
			() -> PropsUtil.get(PropsKeys.DNS_SECURITY_THREAD_QUEUE_LIMIT)
		).thenReturn(
			String.valueOf(5)
		);
	}

	@AfterClass
	public static void tearDownClass() {
		_propsUtilMockedStatic.close();
	}

	@Before
	public void setUp() throws Exception {
		_inetAddressUtilMockedStatic = Mockito.mockStatic(
			InetAddressUtil.class);

		_inetAddressUtilMockedStatic.when(
			() -> InetAddressUtil.getInetAddressByName(Mockito.anyString())
		).thenAnswer(
			invocationOnMock -> {
				String domain = invocationOnMock.getArgument(0);

				if (domain.equals(_HOST_PUBLIC)) {
					return InetAddress.getByName("203.0.113.1");
				}

				if (domain.equals(_HOST_UNKNOWN)) {
					throw new UnknownHostException(domain);
				}

				if (domain.equals(_HOST_UNRESOLVED)) {
					return null;
				}

				return invocationOnMock.callRealMethod();
			}
		);

		_inetAddressUtilMockedStatic.when(
			() -> InetAddressUtil.isLocalInetAddress(
				Mockito.any(InetAddress.class))
		).thenCallRealMethod();
	}

	@After
	public void tearDown() {
		_inetAddressUtilMockedStatic.close();
	}

	@Test
	public void testFetch() throws Exception {
		List<String> locations = new ArrayList<>();

		Assert.assertEquals(
			"content",
			URLFetchSecurityUtil.fetch(
				_createOptions("http://" + _HOST_PUBLIC + "/a"), null, false, 5,
				options -> {
					Assert.assertFalse(options.isFollowRedirects());

					locations.add(options.getLocation());

					if (locations.size() == 1) {
						_setResponse(options, 302, "/b");
					}
					else {
						_setResponse(options, 200, null);
					}

					return "content";
				}));
		Assert.assertEquals(
			Arrays.asList(
				"http://" + _HOST_PUBLIC + "/a",
				"http://" + _HOST_PUBLIC + "/b"),
			locations);

		_assertFetchDenied(
			URLFetchSecurityException.Type.HOST_NOT_ALLOWED, "http://127.0.0.1/", 5,
			options -> {
				throw new AssertionError();
			});
		_assertFetchDenied(
			URLFetchSecurityException.Type.HOST_NOT_ALLOWED, "http://" + _HOST_PUBLIC + "/", 5,
			options -> {
				_setResponse(options, 302, "http://127.0.0.1/");

				return null;
			});
		_assertFetchDenied(
			URLFetchSecurityException.Type.TOO_MANY_REDIRECTS, "http://" + _HOST_PUBLIC + "/", 1,
			options -> {
				_setResponse(options, 302, "/next");

				return null;
			});
	}

	@Test
	public void testIsAllowedURL() {
		_assertAllowedURL("http://" + _HOST_PUBLIC + "/");
		_assertAllowedURL("https://" + _HOST_PUBLIC + ":8443/");
		_assertAllowedURL("https://203.0.113.1/");

		_assertDeniedURL(URLFetchSecurityException.Type.MALFORMED_URL, null);
		_assertDeniedURL(
			URLFetchSecurityException.Type.PROTOCOL_NOT_ALLOWED, "ftp://" + _HOST_PUBLIC + "/");
		_assertDeniedURL(
			URLFetchSecurityException.Type.PROTOCOL_NOT_ALLOWED, "HTTP://" + _HOST_PUBLIC + "/");
		_assertDeniedURL(
			URLFetchSecurityException.Type.HOST_NOT_ALLOWED, "http://" + _HOST_UNRESOLVED + "/");
		_assertDeniedURL(
			URLFetchSecurityException.Type.HOST_UNKNOWN, "http://" + _HOST_UNKNOWN + "/");
		_assertDeniedURL(
			URLFetchSecurityException.Type.HOST_NOT_ALLOWED, "http://10.0.0.1/");
		_assertDeniedURL(
			URLFetchSecurityException.Type.HOST_NOT_ALLOWED, "http://100.64.0.1/");
		_assertDeniedURL(
			URLFetchSecurityException.Type.HOST_NOT_ALLOWED, "http://100.100.100.200/");
		_assertDeniedURL(
			URLFetchSecurityException.Type.HOST_NOT_ALLOWED, "http://127.0.0.1/");
		_assertDeniedURL(
			URLFetchSecurityException.Type.HOST_NOT_ALLOWED, "http://169.254.169.254/");
		_assertDeniedURL(
			URLFetchSecurityException.Type.HOST_NOT_ALLOWED, "http://224.0.0.1/");
		_assertDeniedURL(
			URLFetchSecurityException.Type.HOST_NOT_ALLOWED, "http://[::1]/");
		_assertDeniedURL(
			URLFetchSecurityException.Type.HOST_NOT_ALLOWED, "http://[fd00:ec2::254]/");

		Assert.assertTrue(
			URLFetchSecurityUtil.isAllowedURL("http://127.0.0.1/", null, true));
		Assert.assertFalse(
			URLFetchSecurityUtil.isAllowedURL("http://224.0.0.1/", null, true));

		Assert.assertTrue(
			URLFetchSecurityUtil.isAllowedURL(
				"http://" + _HOST_PUBLIC + "/",
				new String[] {StringUtil.toUpperCase(_HOST_PUBLIC) + ":80"},
				false));
		Assert.assertTrue(
			URLFetchSecurityUtil.isAllowedURL(
				"http://[::1]/", new String[] {"[::1]"}, true));
		Assert.assertTrue(
			URLFetchSecurityUtil.isAllowedURL(
				"http://" + _HOST_PUBLIC + "/", new String[] {"*"}, false));
		Assert.assertFalse(
			URLFetchSecurityUtil.isAllowedURL(
				"http://" + _HOST_PUBLIC + "/", new String[] {"example.com"},
				false));
		Assert.assertFalse(
			URLFetchSecurityUtil.isAllowedURL(
				"http://127.0.0.1/", new String[] {"127.0.0.1"}, false));
	}

	private void _assertAllowedURL(String url) {
		Assert.assertTrue(
			url, URLFetchSecurityUtil.isAllowedURL(url, null, false));
	}

	private void _assertDeniedURL(
		URLFetchSecurityException.Type type, String url) {

		Assert.assertFalse(
			url, URLFetchSecurityUtil.isAllowedURL(url, null, false));

		try {
			URLFetchSecurityUtil.validateURL(url, null, false);

			Assert.fail(url);
		}
		catch (URLFetchSecurityException urlFetchSecurityException) {
			Assert.assertEquals(type, urlFetchSecurityException.getType());
		}
	}

	private void _assertFetchDenied(
			URLFetchSecurityException.Type type, String url, int maxRedirects,
			UnsafeFunction<Http.Options, Object, Exception> fetchUnsafeFunction)
		throws Exception {

		try {
			URLFetchSecurityUtil.fetch(
				_createOptions(url), null, false, maxRedirects,
				fetchUnsafeFunction);

			Assert.fail();
		}
		catch (URLFetchSecurityException urlFetchSecurityException) {
			Assert.assertEquals(type, urlFetchSecurityException.getType());
		}
	}

	private Http.Options _createOptions(String location) {
		Http.Options options = new Http.Options();

		options.setLocation(location);

		return options;
	}

	private void _setResponse(
		Http.Options options, int responseCode, String location) {

		Http.Response response = options.getResponse();

		if (location != null) {
			response.addHeader("Location", location);
		}

		response.setResponseCode(responseCode);
	}

	private static final String _HOST_UNKNOWN = "unknown.example.com";

	private static final String _HOST_PUBLIC = "public.example.com";

	private static final String _HOST_UNRESOLVED = "unresolved.example.com";

	private static final MockedStatic<PropsUtil> _propsUtilMockedStatic =
		Mockito.mockStatic(PropsUtil.class);

	private MockedStatic<InetAddressUtil> _inetAddressUtilMockedStatic;

}