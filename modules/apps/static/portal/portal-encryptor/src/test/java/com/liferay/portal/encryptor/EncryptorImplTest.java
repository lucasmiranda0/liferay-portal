/**
 * SPDX-FileCopyrightText: (c) 2000 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.encryptor;

import com.liferay.portal.kernel.encryptor.Encryptor;
import com.liferay.portal.kernel.test.ReflectionTestUtil;
import com.liferay.portal.kernel.util.PropsValues;
import com.liferay.portal.test.rule.LiferayUnitTestRule;

import java.security.Key;
import java.security.Security;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

/**
 * @author Mika Koivisto
 */
public class EncryptorImplTest {

	@ClassRule
	@Rule
	public static final LiferayUnitTestRule liferayUnitTestRule =
		LiferayUnitTestRule.INSTANCE;

	@Before
	public void setUp() {
		_fipsEnabled = PropsValues.FIPS_ENABLED;
	}

	@After
	public void tearDown() {
		_setFIPSEnabled(_fipsEnabled);
	}

	@Test
	public void testGCMRoundTripWhenFIPSEnabled() throws Exception {
		Assume.assumeNotNull(Security.getProvider("BCFIPS"));

		Encryptor encryptor = new EncryptorImpl();

		Key key = encryptor.generateKey();

		_setFIPSEnabled(true);

		String encryptedString = encryptor.encrypt(key, "Hello World!");

		Assert.assertEquals(
			"Hello World!", encryptor.decrypt(key, encryptedString));
	}

	@Test
	public void testKeySerialization() throws Exception {
		Encryptor encryptor = new EncryptorImpl();

		Key key = encryptor.generateKey();

		String encryptedString = encryptor.encrypt(key, "Hello World!");

		String serializedKey = encryptor.serializeKey(key);

		key = encryptor.deserializeKey(serializedKey);

		Assert.assertEquals(
			"Hello World!", encryptor.decrypt(key, encryptedString));
	}

	@Test
	public void testLegacyCiphertextDecryptsWhenFIPSEnabled() throws Exception {
		Encryptor encryptor = new EncryptorImpl();

		Key key = encryptor.generateKey();

		String encryptedString = encryptor.encrypt(key, "Hello World!");

		// Ciphertext was produced before FIPS was enabled. Enabling FIPS must
		// not break decryption of values already stored in legacy mode.

		_setFIPSEnabled(true);

		Assert.assertEquals(
			"Hello World!", encryptor.decrypt(key, encryptedString));
	}

	private void _setFIPSEnabled(boolean fipsEnabled) {
		ReflectionTestUtil.setFieldValue(
			PropsValues.class, "FIPS_ENABLED", fipsEnabled);
	}

	private boolean _fipsEnabled;

}