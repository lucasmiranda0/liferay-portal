/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.sso.openid.connect.persistence.internal.upgrade.v2_6_0.test;

import com.liferay.arquillian.extension.junit.bridge.junit.Arquillian;
import com.liferay.petra.string.StringBundler;
import com.liferay.portal.kernel.dao.db.DB;
import com.liferay.portal.kernel.dao.db.DBManagerUtil;
import com.liferay.portal.kernel.dao.jdbc.DataAccess;
import com.liferay.portal.kernel.test.util.RandomTestUtil;
import com.liferay.portal.kernel.test.util.TestPropsValues;
import com.liferay.portal.kernel.upgrade.UpgradeProcess;
import com.liferay.portal.test.rule.Inject;
import com.liferay.portal.test.rule.LiferayIntegrationTestRule;
import com.liferay.portal.upgrade.registry.UpgradeStepRegistrator;
import com.liferay.portal.upgrade.test.util.UpgradeTestUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * @author Lucas Miranda
 */
@RunWith(Arquillian.class)
public class OpenIdConnectSessionUpgradeProcessTest {

	@ClassRule
	@Rule
	public static final LiferayIntegrationTestRule integrationTestRule =
		new LiferayIntegrationTestRule();

	@Before
	public void setUp() throws Exception {
		try (Connection connection = DataAccess.getConnection();

			PreparedStatement preparedStatement = connection.prepareStatement(
				StringBundler.concat(
					"insert into OpenIdConnectSession (mvccVersion, ",
					"openIdConnectSessionId, companyId, issuer) values(?, ?, ",
					"?, ?)"))) {

			preparedStatement.setLong(1, 0);
			preparedStatement.setLong(2, _OPEN_ID_CONNECT_SESSION_ID);
			preparedStatement.setLong(3, TestPropsValues.getCompanyId());
			preparedStatement.setString(4, _ISSUER);

			preparedStatement.execute();
		}
	}

	@After
	public void tearDown() throws Exception {
		DB db = DBManagerUtil.getDB();

		db.runSQL(
			"delete from OpenIdConnectSession where openIdConnectSessionId = " +
				_OPEN_ID_CONNECT_SESSION_ID);
	}

	@Test
	public void testUpgrade() throws Exception {
		UpgradeProcess upgradeProcess = UpgradeTestUtil.getUpgradeStep(
			_upgradeStepRegistrator,
			"com.liferay.portal.security.sso.openid.connect.persistence." +
				"internal.upgrade.v2_6_0.OpenIdConnectSessionUpgradeProcess");

		upgradeProcess.upgrade();

		try (Connection connection = DataAccess.getConnection();

			Statement statement = connection.createStatement();

			ResultSet resultSet = statement.executeQuery(
				"select sessionId from OpenIdConnectSession where " +
					"openIdConnectSessionId = " +
						_OPEN_ID_CONNECT_SESSION_ID)) {

			Assert.assertTrue(resultSet.next());

			Assert.assertEquals(
				"liferay-" + _OPEN_ID_CONNECT_SESSION_ID,
				resultSet.getString("sessionId"));
		}
	}

	private static final String _ISSUER = RandomTestUtil.randomString();

	private static final long _OPEN_ID_CONNECT_SESSION_ID =
		RandomTestUtil.randomLong();

	@Inject(
		filter = "component.name=com.liferay.portal.security.sso.openid.connect.persistence.internal.upgrade.registry.OpenIdConnectServiceUpgradeStepRegistrator"
	)
	private UpgradeStepRegistrator _upgradeStepRegistrator;

}