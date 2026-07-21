/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.instance.lifecycle;

import com.liferay.portal.instance.lifecycle.BasePortalInstanceLifecycleListener;
import com.liferay.portal.instance.lifecycle.PortalInstanceLifecycleListener;
import com.liferay.portal.kernel.language.Language;
import com.liferay.portal.kernel.model.Company;
import com.liferay.portal.kernel.model.ResourceConstants;
import com.liferay.portal.kernel.model.ResourcePermission;
import com.liferay.portal.kernel.model.Role;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.model.role.RoleConstants;
import com.liferay.portal.kernel.service.ResourcePermissionLocalService;
import com.liferay.portal.kernel.service.RoleLocalService;
import com.liferay.portal.kernel.util.HashMapBuilder;
import com.liferay.portal.kernel.util.PortletKeys;
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
		long companyId = company.getCompanyId();

		Role role = _roleLocalService.fetchRole(companyId, _ROLE_NAME);

		if (role == null) {
			User guestUser = company.getGuestUser();

			role = _roleLocalService.addRole(
				null, guestUser.getUserId(), null, 0, _ROLE_NAME, null,
				HashMapBuilder.put(
					company.getLocale(),
					_language.get(company.getLocale(), "crypto-officer")
				).build(),
				RoleConstants.TYPE_REGULAR, null, null);
		}

		ResourcePermission resourcePermission =
			_resourcePermissionLocalService.fetchResourcePermission(
				companyId, PortletKeys.PORTAL, ResourceConstants.SCOPE_COMPANY,
				String.valueOf(companyId), role.getRoleId());

		if (resourcePermission != null) {
			return;
		}

		_resourcePermissionLocalService.addResourcePermission(
			companyId, PortletKeys.PORTAL, ResourceConstants.SCOPE_COMPANY,
			String.valueOf(companyId), role.getRoleId(),
			FIPSActionKeys.TRIGGER_HEALTH_VERIFICATION);
	}

	private static final String _ROLE_NAME = "Crypto Officer";

	@Reference
	private Language _language;

	@Reference
	private ResourcePermissionLocalService _resourcePermissionLocalService;

	@Reference
	private RoleLocalService _roleLocalService;

}