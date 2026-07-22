/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.instance.lifecycle;

import com.liferay.portal.instance.lifecycle.BasePortalInstanceLifecycleListener;
import com.liferay.portal.instance.lifecycle.PortalInstanceLifecycleListener;
import com.liferay.portal.kernel.language.Language;
import com.liferay.portal.kernel.model.Company;
import com.liferay.portal.kernel.model.Role;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.model.role.RoleConstants;
import com.liferay.portal.kernel.service.RoleLocalService;
import com.liferay.portal.kernel.util.HashMapBuilder;
import com.liferay.portal.security.fips.rest.internal.constants.FIPSActionKeys;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * @author Lucas Miranda
 */
@Component(service = PortalInstanceLifecycleListener.class)
public class CryptoOfficerRolePortalInstanceLifecycleListener
	extends BasePortalInstanceLifecycleListener {

	@Override
	public void portalInstanceRegistered(Company company) throws Exception {
		Role role = _roleLocalService.fetchRole(
			company.getCompanyId(), FIPSActionKeys.CRYPTO_OFFICER_ROLE_NAME);

		if (role != null) {
			return;
		}

		User guestUser = company.getGuestUser();

		_roleLocalService.addRole(
			null, guestUser.getUserId(), null, 0,
			FIPSActionKeys.CRYPTO_OFFICER_ROLE_NAME, null,
			HashMapBuilder.put(
				company.getLocale(),
				_language.get(company.getLocale(), "crypto-officer")
			).build(),
			RoleConstants.TYPE_REGULAR, null, null);
	}

	@Reference
	private Language _language;

	@Reference
	private RoleLocalService _roleLocalService;

}