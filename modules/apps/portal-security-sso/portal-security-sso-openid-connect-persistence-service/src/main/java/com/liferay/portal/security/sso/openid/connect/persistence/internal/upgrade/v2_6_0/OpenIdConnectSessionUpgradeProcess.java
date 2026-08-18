/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.sso.openid.connect.persistence.internal.upgrade.v2_6_0;

import com.liferay.portal.kernel.dao.jdbc.AutoBatchPreparedStatementUtil;
import com.liferay.portal.kernel.upgrade.UpgradeProcess;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * @author Lucas Miranda
 */
public class OpenIdConnectSessionUpgradeProcess extends UpgradeProcess {

	@Override
	protected void doUpgrade() throws Exception {
		try (Statement statement = connection.createStatement();

			ResultSet resultSet = statement.executeQuery(
				"select openIdConnectSessionId from OpenIdConnectSession " +
					"where sessionId is null");

			PreparedStatement preparedStatement =
				AutoBatchPreparedStatementUtil.concurrentAutoBatch(
					connection,
					"update OpenIdConnectSession set sessionId = ? where " +
						"openIdConnectSessionId = ?")) {

			while (resultSet.next()) {
				long openIdConnectSessionId = resultSet.getLong(
					"openIdConnectSessionId");

				preparedStatement.setString(
					1, _SESSION_ID_PREFIX + openIdConnectSessionId);

				preparedStatement.setLong(2, openIdConnectSessionId);

				preparedStatement.addBatch();
			}

			preparedStatement.executeBatch();
		}
	}

	// Must match OfflineOpenIdConnectSessionManager, which lives in another
	// bundle and generates the same value for sessions the identity provider
	// issues no "sid" claim for

	private static final String _SESSION_ID_PREFIX = "liferay-";

}