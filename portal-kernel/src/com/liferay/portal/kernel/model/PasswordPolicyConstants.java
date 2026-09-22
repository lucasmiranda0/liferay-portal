/**
 * SPDX-FileCopyrightText: (c) 2000 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.model;

import com.liferay.portal.kernel.util.ArrayUtil;

/**
 * @author Scott Lee
 */
public class PasswordPolicyConstants {

	public static final String CRYPTO_OFFICER_PASSWORD_POLICY =
		"Crypto Officer Password Policy";

	public static final String DEFAULT_PASSWORD_POLICY =
		"Default Password Policy";

	public static final String[] SYSTEM_PASSWORD_POLICIES = {
		DEFAULT_PASSWORD_POLICY
	};

	public static boolean isUnmodifiable(String passwordPolicyName) {
		return ArrayUtil.contains(
			_UNMODIFIABLE_PASSWORD_POLICY_NAMES, passwordPolicyName);
	}

	private static final String[] _UNMODIFIABLE_PASSWORD_POLICY_NAMES = {
		CRYPTO_OFFICER_PASSWORD_POLICY
	};

}