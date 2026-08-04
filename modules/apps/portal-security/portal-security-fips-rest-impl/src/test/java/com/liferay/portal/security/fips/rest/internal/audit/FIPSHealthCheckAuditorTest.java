/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.audit;

import com.liferay.portal.kernel.audit.AuditException;
import com.liferay.portal.kernel.audit.AuditMessage;
import com.liferay.portal.kernel.audit.AuditRouter;
import com.liferay.portal.kernel.json.JSONObject;
import com.liferay.portal.kernel.security.fips.FIPSHealthCheckResult;
import com.liferay.portal.kernel.security.fips.FIPSModeValidator;
import com.liferay.portal.kernel.test.ReflectionTestUtil;
import com.liferay.portal.test.rule.LiferayUnitTestRule;

import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

/**
 * @author Lucas Miranda
 */
public class FIPSHealthCheckAuditorTest {

	@ClassRule
	@Rule
	public static final LiferayUnitTestRule liferayUnitTestRule =
		LiferayUnitTestRule.INSTANCE;

	@Before
	public void setUp() {
		_auditRouter = Mockito.mock(AuditRouter.class);

		_fipsHealthCheckAuditor = new FIPSHealthCheckAuditor();

		ReflectionTestUtil.setFieldValue(
			_fipsHealthCheckAuditor, "_auditRouter", _auditRouter);
	}

	@Test
	public void testAudit() throws Exception {
		_fipsHealthCheckAuditor.audit(
			FIPSHealthCheckResult.failed(
				"BCFIPS", "AES-KAT", "NOT_APPROVED", "boom"));

		ArgumentCaptor<AuditMessage> argumentCaptor = ArgumentCaptor.forClass(
			AuditMessage.class);

		Mockito.verify(
			_auditRouter
		).route(
			argumentCaptor.capture()
		);

		AuditMessage auditMessage = argumentCaptor.getValue();

		Assert.assertEquals(
			"periodic-health-failure", auditMessage.getEventType());
		Assert.assertEquals(
			FIPSModeValidator.class.getName(), auditMessage.getClassName());
		Assert.assertEquals("0", auditMessage.getClassPK());

		JSONObject additionalInfoJSONObject = auditMessage.getAdditionalInfo();

		Assert.assertEquals(
			"critical", additionalInfoJSONObject.getString("severity"));
		Assert.assertEquals(
			"AES-KAT", additionalInfoJSONObject.getString("failedTest"));
		Assert.assertEquals(
			"NOT_APPROVED", additionalInfoJSONObject.getString("fipsState"));
		Assert.assertEquals(
			"BCFIPS", additionalInfoJSONObject.getString("providerName"));
		Assert.assertEquals(
			"boom", additionalInfoJSONObject.getString("providerMessage"));
	}

	@Test
	public void testAuditSwallowsAuditException() throws Exception {
		Mockito.doThrow(
			new AuditException()
		).when(
			_auditRouter
		).route(
			Mockito.any()
		);

		_fipsHealthCheckAuditor.audit(
			FIPSHealthCheckResult.failed(
				"BCFIPS", "AES-KAT", "NOT_APPROVED", "boom"));
	}

	private AuditRouter _auditRouter;
	private FIPSHealthCheckAuditor _fipsHealthCheckAuditor;

}