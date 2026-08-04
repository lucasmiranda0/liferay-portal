/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.error;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.security.fips.FIPSHealthCheckResult;

import org.osgi.service.component.annotations.Component;

/**
 * @author Lucas Miranda
 */
@Component(service = FIPSErrorStateTrigger.class)
public class LoggingFIPSErrorStateTrigger implements FIPSErrorStateTrigger {

	@Override
	public void enterErrorState(FIPSHealthCheckResult fipsHealthCheckResult) {

		// No-op seam. LPD-99824 wires the real FIPS Error State transition
		// (LPD-93276) here.

		if (_log.isWarnEnabled()) {
			_log.warn(
				String.format(
					"The FIPS Error State transition seam was invoked for " +
						"failed test \"%s\"",
					fipsHealthCheckResult.getFailedTest()));
		}
	}

	private static final Log _log = LogFactoryUtil.getLog(
		LoggingFIPSErrorStateTrigger.class);

}