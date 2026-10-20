/**
 * SPDX-FileCopyrightText: (c) 2000 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.util;

import com.liferay.petra.function.UnsafeFunction;
import com.liferay.petra.string.StringBundler;
import com.liferay.petra.string.StringPool;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

import java.util.Objects;

/**
 * @author Lucas Miranda
 */
public class URLFetchSecurityUtil {

	public static <T> T fetch(
			Http.Options options, String[] hostsAllowed,
			boolean localNetworkAccessEnabled, int maxRedirects,
			UnsafeFunction<Http.Options, T, Exception> fetchUnsafeFunction)
		throws Exception {

		String location = options.getLocation();

		URL url = validateURL(
			location, hostsAllowed, localNetworkAccessEnabled);

		options.setFollowRedirects(false);

		for (int i = 0;; i++) {
			options.setLocation(url.toString());

			T t = fetchUnsafeFunction.apply(options);

			String redirectLocation = _getRedirectLocation(
				options.getResponse());

			if (Validator.isNull(redirectLocation)) {
				return t;
			}

			if (i >= maxRedirects) {
				throw new URLFetchSecurityException(
					StringBundler.concat(
						"Denied access to ", location,
						" because of too many redirects"),
					URLFetchSecurityException.Type.TOO_MANY_REDIRECTS,
					location, url.getHost());
			}

			url = validateURL(
				String.valueOf(new URL(url, redirectLocation)), hostsAllowed,
				localNetworkAccessEnabled);
		}
	}

	public static boolean isAllowedURL(
		String urlString, String[] hostsAllowed,
		boolean localNetworkAccessEnabled) {

		try {
			validateURL(urlString, hostsAllowed, localNetworkAccessEnabled);

			return true;
		}
		catch (URLFetchSecurityException urlFetchSecurityException) {
			if (_log.isDebugEnabled()) {
				_log.debug(urlFetchSecurityException);
			}

			return false;
		}
	}

	public static boolean isLocalInetAddress(InetAddress inetAddress) {
		if (InetAddressUtil.isLocalInetAddress(inetAddress) ||
			inetAddress.isMulticastAddress()) {

			return true;
		}

		byte[] address = inetAddress.getAddress();

		if (address.length == 4) {
			if ((address[0] == 100) && ((address[1] & 0xc0) == 0x40)) {
				return true;
			}

			return false;
		}

		if ((address[0] & 0xfe) == 0xfc) {
			return true;
		}

		return false;
	}

	public static URL validateURL(
			String urlString, String[] hostsAllowed,
			boolean localNetworkAccessEnabled)
		throws URLFetchSecurityException {

		URL url = null;

		try {
			url = new URL(urlString);
		}
		catch (MalformedURLException malformedURLException) {
			throw new URLFetchSecurityException(
				"Denied access to malformed URL " + urlString,
				URLFetchSecurityException.Type.MALFORMED_URL, urlString, null,
				malformedURLException);
		}

		String host = _normalizeHost(url.getHost());
		String protocol = url.getProtocol();

		if (!urlString.startsWith(protocol + StringPool.COLON) ||
			(!Objects.equals(protocol, Http.HTTP) &&
			 !Objects.equals(protocol, Http.HTTPS))) {

			throw new URLFetchSecurityException(
				StringBundler.concat(
					"Denied access to ", urlString, " because protocol ",
					protocol, " is not allowed"),
				URLFetchSecurityException.Type.PROTOCOL_NOT_ALLOWED, urlString,
				host);
		}

		if (Validator.isNull(host) || !_isHostAllowed(hostsAllowed, host)) {
			throw _createHostNotAllowedURLFetchSecurityException(
				urlString, host);
		}

		InetAddress inetAddress = null;

		try {
			inetAddress = InetAddressUtil.getInetAddressByName(host);
		}
		catch (UnknownHostException unknownHostException) {
			throw new URLFetchSecurityException(
				StringBundler.concat(
					"Denied access to ", urlString, " because host ", host,
					" is unknown"),
				URLFetchSecurityException.Type.HOST_UNKNOWN, urlString, host,
				unknownHostException);
		}

		if ((inetAddress == null) || inetAddress.isMulticastAddress() ||
			(!localNetworkAccessEnabled && isLocalInetAddress(inetAddress))) {

			throw _createHostNotAllowedURLFetchSecurityException(
				urlString, host);
		}

		return url;
	}

	private static URLFetchSecurityException
		_createHostNotAllowedURLFetchSecurityException(
			String urlString, String host) {

		return new URLFetchSecurityException(
			StringBundler.concat(
				"Denied access to ", urlString, " because host ", host,
				" is not allowed"),
			URLFetchSecurityException.Type.HOST_NOT_ALLOWED, urlString, host);
	}

	private static String _getRedirectLocation(Http.Response response) {
		if (response == null) {
			return null;
		}

		int responseCode = response.getResponseCode();

		if ((responseCode < 300) || (responseCode >= 400)) {
			return null;
		}

		return response.getHeader("Location");
	}

	private static boolean _isHostAllowed(String[] hostsAllowed, String host) {
		if (ArrayUtil.isEmpty(hostsAllowed)) {
			return true;
		}

		for (String hostAllowed : hostsAllowed) {
			String normalizedHostAllowed = _normalizeHost(hostAllowed);

			if (Objects.equals(normalizedHostAllowed, StringPool.STAR) ||
				StringUtil.equalsIgnoreCase(normalizedHostAllowed, host)) {

				return true;
			}
		}

		return false;
	}

	private static String _normalizeHost(String host) {
		if (Validator.isBlank(host)) {
			return StringPool.BLANK;
		}

		host = host.trim();

		if (host.startsWith(StringPool.OPEN_BRACKET)) {
			int index = host.indexOf(StringPool.CLOSE_BRACKET);

			if (index > 1) {
				return host.substring(1, index);
			}

			return host;
		}

		int index = host.indexOf(StringPool.COLON);

		if ((index > 0) && (host.indexOf(StringPool.COLON, index + 1) < 0)) {
			return host.substring(0, index);
		}

		return host;
	}

	private static final Log _log = LogFactoryUtil.getLog(
		URLFetchSecurityUtil.class);

}