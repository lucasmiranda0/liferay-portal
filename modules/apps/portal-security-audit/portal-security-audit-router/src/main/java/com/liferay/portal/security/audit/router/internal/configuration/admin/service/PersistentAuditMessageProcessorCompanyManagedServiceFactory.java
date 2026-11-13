/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.audit.router.internal.configuration.admin.service;

import com.liferay.portal.configuration.metatype.bnd.util.ConfigurableUtil;
import com.liferay.portal.kernel.util.GetterUtil;
import com.liferay.portal.security.audit.router.configuration.PersistentAuditMessageProcessorCompanyConfiguration;

import java.util.Dictionary;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.osgi.framework.Constants;
import org.osgi.service.cm.ManagedServiceFactory;
import org.osgi.service.component.annotations.Component;

/**
 * @author Lucas Miranda
 */
@Component(
	property = Constants.SERVICE_PID + "=com.liferay.portal.security.audit.router.configuration.PersistentAuditMessageProcessorCompanyConfiguration.scoped",
	service = ManagedServiceFactory.class
)
public class PersistentAuditMessageProcessorCompanyManagedServiceFactory
	implements ManagedServiceFactory {

	@Override
	public void deleted(String pid) {
		Long companyId = _companyIds.remove(pid);

		if (companyId != null) {
			_disabledCompanyIds.remove(companyId);
		}
	}

	@Override
	public String getName() {
		return "com.liferay.portal.security.audit.router.configuration." +
			"PersistentAuditMessageProcessorCompanyConfiguration.scoped";
	}

	public boolean isEnabled(long companyId) {
		return !_disabledCompanyIds.contains(companyId);
	}

	@Override
	public void updated(String pid, Dictionary<String, ?> dictionary) {
		deleted(pid);

		PersistentAuditMessageProcessorCompanyConfiguration
			persistentAuditMessageProcessorCompanyConfiguration =
				ConfigurableUtil.createConfigurable(
					PersistentAuditMessageProcessorCompanyConfiguration.class,
					dictionary);

		if (!persistentAuditMessageProcessorCompanyConfiguration.enabled()) {
			long companyId = GetterUtil.getLong(dictionary.get("companyId"));

			_companyIds.put(pid, companyId);
			_disabledCompanyIds.add(companyId);
		}
	}

	private final Map<String, Long> _companyIds = new ConcurrentHashMap<>();
	private final Set<Long> _disabledCompanyIds = ConcurrentHashMap.newKeySet();

}