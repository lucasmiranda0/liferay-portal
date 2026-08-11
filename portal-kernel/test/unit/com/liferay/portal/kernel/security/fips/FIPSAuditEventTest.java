/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.security.fips;

import com.liferay.portal.kernel.test.util.RandomTestUtil;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.util.Map;

import javax.crypto.spec.PBEKeySpec;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Jorge García Jiménez
 */
public class FIPSAuditEventTest {

	@Test
	public void testPut() {
		FIPSAuditEvent fipsAuditEvent = new FIPSAuditEvent(
			RandomTestUtil.randomString(), FIPSAuditEvent.Severity.INFO);

		String reason = RandomTestUtil.randomString();

		fipsAuditEvent.put("reason", reason);

		Map<String, Object> fields = fipsAuditEvent.getFields();

		Assert.assertEquals(reason, fields.get("reason"));
	}

	@Test
	public void testPutRejectsASensitiveSecurityParameter() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		_testPutRejectsASensitiveSecurityParameter(keyPair.getPrivate());
		_testPutRejectsASensitiveSecurityParameter(keyPair.getPublic());

		char[] chars = RandomTestUtil.randomString(
		).toCharArray();

		_testPutRejectsASensitiveSecurityParameter(
			RandomTestUtil.randomBytes());
		_testPutRejectsASensitiveSecurityParameter(chars);
		_testPutRejectsASensitiveSecurityParameter(new PBEKeySpec(chars));
	}

	private void _testPutRejectsASensitiveSecurityParameter(Object value) {
		FIPSAuditEvent fipsAuditEvent = new FIPSAuditEvent(
			RandomTestUtil.randomString(), FIPSAuditEvent.Severity.INFO);

		Assert.assertThrows(
			IllegalArgumentException.class,
			() -> fipsAuditEvent.put(RandomTestUtil.randomString(), value));

		Map<String, Object> fields = fipsAuditEvent.getFields();

		Assert.assertTrue(String.valueOf(fields), fields.isEmpty());
	}

}