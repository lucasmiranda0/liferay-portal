/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.auth.tunnel;

import com.liferay.portal.kernel.security.auth.AuthException;
import com.liferay.portal.kernel.test.ReflectionTestUtil;
import com.liferay.portal.kernel.util.PropsValues;
import com.liferay.portal.test.rule.LiferayUnitTestRule;

import java.security.Key;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

/**
 * @author Lucas Miranda
 */
public class TunnelAuthenticationManagerImplTest {

	@ClassRule
	@Rule
	public static final LiferayUnitTestRule liferayUnitTestRule =
		LiferayUnitTestRule.INSTANCE;

	@Before
	public void setUp() {
		_fipsEnabled = PropsValues.FIPS_ENABLED;
		_sharedSecret = PropsValues.TUNNELING_SERVLET_SHARED_SECRET;
		_sharedSecretHex = PropsValues.TUNNELING_SERVLET_SHARED_SECRET_HEX;
		_encryptionAlgorithm =
			PropsValues.TUNNELING_SERVLET_ENCRYPTION_ALGORITHM;

		_setField("TUNNELING_SERVLET_SHARED_SECRET", "0123456789abcdef");
		_setField("TUNNELING_SERVLET_SHARED_SECRET_HEX", false);
	}

	@After
	public void tearDown() {
		_setField("FIPS_ENABLED", _fipsEnabled);
		_setField("TUNNELING_SERVLET_SHARED_SECRET", _sharedSecret);
		_setField("TUNNELING_SERVLET_SHARED_SECRET_HEX", _sharedSecretHex);
		_setField(
			"TUNNELING_SERVLET_ENCRYPTION_ALGORITHM", _encryptionAlgorithm);
	}

	@Test
	public void testApprovedAlgorithmAllowedWhenFIPSEnabled() throws Exception {
		_setField("FIPS_ENABLED", true);
		_setField("TUNNELING_SERVLET_ENCRYPTION_ALGORITHM", "AES");

		Key key = new TunnelAuthenticationManagerImpl(
		).getSharedSecretKey();

		Assert.assertEquals("AES", key.getAlgorithm());
	}

	@Test
	public void testUnapprovedAlgorithmAllowedWhenFIPSDisabled()
		throws Exception {

		_setField("FIPS_ENABLED", false);
		_setField("TUNNELING_SERVLET_ENCRYPTION_ALGORITHM", "Blowfish");

		Key key = new TunnelAuthenticationManagerImpl(
		).getSharedSecretKey();

		Assert.assertEquals("Blowfish", key.getAlgorithm());
	}

	@Test(expected = AuthException.class)
	public void testUnapprovedAlgorithmRejectedWhenFIPSEnabled()
		throws Exception {

		_setField("FIPS_ENABLED", true);
		_setField("TUNNELING_SERVLET_ENCRYPTION_ALGORITHM", "Blowfish");

		try {
			new TunnelAuthenticationManagerImpl(
			).getSharedSecretKey();
		}
		catch (AuthException authException) {
			Assert.assertEquals(
				AuthException.INVALID_SHARED_SECRET, authException.getType());

			throw authException;
		}
	}

	private void _setField(String name, Object value) {
		ReflectionTestUtil.setFieldValue(PropsValues.class, name, value);
	}

	private String _encryptionAlgorithm;
	private boolean _fipsEnabled;
	private String _sharedSecret;
	private boolean _sharedSecretHex;

}