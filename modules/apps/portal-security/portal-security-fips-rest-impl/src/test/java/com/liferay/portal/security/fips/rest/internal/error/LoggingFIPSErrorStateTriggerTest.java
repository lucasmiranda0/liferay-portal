/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.error;

import com.liferay.portal.kernel.security.fips.FIPSHealthCheckResult;
import com.liferay.portal.test.log.LogCapture;
import com.liferay.portal.test.log.LogEntry;
import com.liferay.portal.test.log.LoggerTestUtil;
import com.liferay.portal.test.rule.LiferayUnitTestRule;

import java.util.List;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

/**
 * @author Lucas Miranda
 */
public class LoggingFIPSErrorStateTriggerTest {

	@ClassRule
	public static final LiferayUnitTestRule liferayUnitTestRule =
		LiferayUnitTestRule.INSTANCE;

	@Test
	public void testEnterErrorState() {
		FIPSErrorStateTrigger fipsErrorStateTrigger =
			new LoggingFIPSErrorStateTrigger();

		try (LogCapture logCapture = LoggerTestUtil.configureLog4JLogger(
				LoggingFIPSErrorStateTrigger.class.getName(),
				LoggerTestUtil.WARN)) {

			fipsErrorStateTrigger.enterErrorState(
				FIPSHealthCheckResult.failed(
					"BCFIPS", "AES-KAT", "NOT_APPROVED", "boom"));

			List<LogEntry> logEntries = logCapture.getLogEntries();

			Assert.assertEquals(logEntries.toString(), 1, logEntries.size());

			LogEntry logEntry = logEntries.get(0);

			Assert.assertTrue(
				logEntry.getMessage(),
				logEntry.getMessage(
				).contains(
					"AES-KAT"
				));
		}
	}

}