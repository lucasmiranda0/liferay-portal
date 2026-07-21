/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.audit;

import com.liferay.portal.kernel.audit.AuditMessage;
import com.liferay.portal.kernel.json.JSONFactory;
import com.liferay.portal.kernel.json.JSONObject;
import com.liferay.portal.kernel.security.fips.FIPSHealthCheckResult;
import com.liferay.portal.kernel.security.fips.FIPSModeValidator;

/**
 * @author Lucas Miranda
 */
public class FIPSHealthAuditMessageBuilder {

	public static AuditMessage build(
		long companyId, long userId, String userName,
		FIPSHealthCheckResult result, JSONFactory jsonFactory) {

		JSONObject additionalInfoJSONObject = jsonFactory.createJSONObject();

		additionalInfoJSONObject.put(
			"failedTest", result.getFailedTest()
		).put(
			"fipsState", result.getFipsState()
		).put(
			"providerMessage", result.getProviderMessage()
		).put(
			"providerName", result.getProviderName()
		).put(
			"severity", "CRITICAL"
		);

		return new AuditMessage(
			companyId, userId, userName, additionalInfoJSONObject,
			FIPSModeValidator.class.getName(), "0", _EVENT_TYPE, null);
	}

	private static final String _EVENT_TYPE = "periodic-health-failure";

}