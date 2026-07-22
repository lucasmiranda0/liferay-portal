/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.audit;

import com.liferay.portal.kernel.audit.AuditMessage;
import com.liferay.portal.kernel.json.JSONFactory;
import com.liferay.portal.kernel.json.JSONObject;
import com.liferay.portal.kernel.security.fips.FIPSHealthCheckResult;
import com.liferay.portal.test.rule.LiferayUnitTestRule;

import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.mockito.Mockito;

/**
 * @author Lucas Miranda
 */
public class FIPSHealthAuditMessageBuilderTest {

	@ClassRule
	@Rule
	public static final LiferayUnitTestRule liferayUnitTestRule =
		LiferayUnitTestRule.INSTANCE;

	@Before
	public void setUp() {
		_jsonObject = Mockito.mock(JSONObject.class);

		Mockito.when(
			_jsonObject.put(Mockito.anyString(), Mockito.nullable(String.class))
		).thenReturn(
			_jsonObject
		);

		_jsonFactory = Mockito.mock(JSONFactory.class);

		Mockito.when(
			_jsonFactory.createJSONObject()
		).thenReturn(
			_jsonObject
		);
	}

	@Test
	public void testBuild() {
		FIPSHealthCheckResult result = FIPSHealthCheckResult.failed(
			"BCFIPS", "AES-KAT", "ERROR", "boom");

		AuditMessage auditMessage = FIPSHealthAuditMessageBuilder.build(
			123L, 456L, "Test User", result, _jsonFactory);

		Assert.assertEquals(
			"periodic-health-failure", auditMessage.getEventType());
		Assert.assertEquals(123L, auditMessage.getCompanyId());
		Assert.assertEquals(456L, auditMessage.getUserId());
		Assert.assertEquals(
			"com.liferay.portal.kernel.security.fips.FIPSModeValidator",
			auditMessage.getClassName());

		Mockito.verify(
			_jsonObject
		).put(
			"severity", "CRITICAL"
		);

		Mockito.verify(
			_jsonObject
		).put(
			"failedTest", "AES-KAT"
		);

		Mockito.verify(
			_jsonObject
		).put(
			"fipsState", "ERROR"
		);

		Mockito.verify(
			_jsonObject
		).put(
			"providerMessage", "boom"
		);

		Mockito.verify(
			_jsonObject
		).put(
			"providerName", "BCFIPS"
		);
	}

	private JSONFactory _jsonFactory;
	private JSONObject _jsonObject;

}