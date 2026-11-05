/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.audit.event.generators.user.management.internal.service;

import com.liferay.petra.sql.dsl.DSLQueryFactoryUtil;
import com.liferay.petra.string.StringPool;
import com.liferay.portal.kernel.audit.AuditMessage;
import com.liferay.portal.kernel.audit.AuditRouter;
import com.liferay.portal.kernel.exception.SystemException;
import com.liferay.portal.kernel.model.PortalPreferenceValue;
import com.liferay.portal.kernel.model.PortalPreferenceValueTable;
import com.liferay.portal.kernel.model.PortalPreferences;
import com.liferay.portal.kernel.service.PortalPreferenceValueLocalService;
import com.liferay.portal.kernel.service.ServiceWrapper;
import com.liferay.portal.kernel.util.PortletKeys;
import com.liferay.portal.kernel.util.PropsUtil;
import com.liferay.portal.kernel.util.Validator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * @author Lucas Miranda
 */
@Component(service = ServiceWrapper.class)
public class PortalPreferencesLocalServiceWrapper
	extends com.liferay.portal.kernel.service.
				PortalPreferencesLocalServiceWrapper {

	@Override
	public PortalPreferences updatePreferences(
		long ownerId, int ownerType,
		com.liferay.portal.kernel.portlet.PortalPreferences portalPreferences) {

		return _updatePreferences(
			ownerId, ownerType,
			() -> super.updatePreferences(
				ownerId, ownerType, portalPreferences));
	}

	@Override
	public PortalPreferences updatePreferences(
		long ownerId, int ownerType, String xml) {

		return _updatePreferences(
			ownerId, ownerType,
			() -> super.updatePreferences(ownerId, ownerType, xml));
	}

	private Map<String, List<String>> _getValuesMap(
		PortalPreferences portalPreferences) {

		if (portalPreferences == null) {
			return Collections.emptyMap();
		}

		Map<String, List<String>> valuesMap = new HashMap<>();

		List<PortalPreferenceValue> portalPreferenceValues =
			_portalPreferenceValueLocalService.dslQuery(
				DSLQueryFactoryUtil.select(
					PortalPreferenceValueTable.INSTANCE
				).from(
					PortalPreferenceValueTable.INSTANCE
				).where(
					PortalPreferenceValueTable.INSTANCE.portalPreferencesId.eq(
						portalPreferences.getPortalPreferencesId())
				).orderBy(
					PortalPreferenceValueTable.INSTANCE.index.ascending()
				));

		for (PortalPreferenceValue portalPreferenceValue :
				portalPreferenceValues) {

			String key = portalPreferenceValue.getKey();

			if (Validator.isNotNull(portalPreferenceValue.getNamespace())) {
				key =
					portalPreferenceValue.getNamespace() + StringPool.POUND +
						key;
			}

			List<String> values = valuesMap.computeIfAbsent(
				key, curKey -> new ArrayList<>());

			values.add(portalPreferenceValue.getValue());
		}

		return valuesMap;
	}

	private PortalPreferences _updatePreferences(
		long ownerId, int ownerType,
		Supplier<PortalPreferences> portalPreferencesSupplier) {

		if (ownerType != PortletKeys.PREFS_OWNER_TYPE_COMPANY) {
			return portalPreferencesSupplier.get();
		}

		Map<String, List<String>> oldValuesMap = _getValuesMap(
			fetchPortalPreferences(ownerId, ownerType));

		PortalPreferences portalPreferences = portalPreferencesSupplier.get();

		AuditMessage auditMessage = InstanceSettingsAuditUtil.buildAuditMessage(
			PortalPreferences.class.getName(),
			portalPreferences.getPortalPreferencesId(), ownerId,
			key -> {
				String value = PropsUtil.get(key);

				if (value == null) {
					return null;
				}

				return Collections.singletonList(value);
			},
			_getValuesMap(portalPreferences), oldValuesMap);

		if (auditMessage == null) {
			return portalPreferences;
		}

		try {
			_auditRouter.route(auditMessage);
		}
		catch (Exception exception) {
			throw new SystemException(exception);
		}

		return portalPreferences;
	}

	@Reference
	private AuditRouter _auditRouter;

	@Reference
	private PortalPreferenceValueLocalService
		_portalPreferenceValueLocalService;

}