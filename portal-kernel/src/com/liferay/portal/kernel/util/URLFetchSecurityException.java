/**
 * SPDX-FileCopyrightText: (c) 2000 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.util;

import java.io.IOException;

/**
 * @author Lucas Miranda
 */
public class URLFetchSecurityException extends IOException {

	public URLFetchSecurityException(
		String message, Type type, String url, String host) {

		super(message);

		_type = type;
		_url = url;
		_host = host;
	}

	public URLFetchSecurityException(
		String message, Type type, String url, String host,
		Throwable throwable) {

		super(message, throwable);

		_type = type;
		_url = url;
		_host = host;
	}

	public String getHost() {
		return _host;
	}

	public Type getType() {
		return _type;
	}

	public String getURL() {
		return _url;
	}

	public enum Type {

		HOST_NOT_ALLOWED, HOST_UNKNOWN, MALFORMED_URL, PROTOCOL_NOT_ALLOWED,
		TOO_MANY_REDIRECTS

	}

	private final String _host;
	private final Type _type;
	private final String _url;

}
