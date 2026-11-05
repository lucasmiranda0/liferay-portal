/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.audit.event.generators.user.management.internal.service;

import com.liferay.portal.kernel.audit.AuditMessage;
import com.liferay.portal.security.audit.event.generators.constants.EventTypes;
import com.liferay.portal.security.audit.event.generators.util.Attribute;
import com.liferay.portal.security.audit.event.generators.util.AuditMessageBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

/**
 * @author Lucas Miranda
 */
public class InstanceSettingsAuditUtil {

	public static AuditMessage buildAuditMessage(
		String className, long classPK, long companyId,
		Function<String, List<String>> defaultValuesFunction,
		Map<String, List<String>> newValuesMap,
		Map<String, List<String>> oldValuesMap) {

		Set<String> keys = new TreeSet<>(newValuesMap.keySet());

		keys.addAll(oldValuesMap.keySet());

		List<Attribute> attributes = new ArrayList<>();

		for (String key : keys) {
			List<String> defaultValues = defaultValuesFunction.apply(key);

			if (Objects.equals(
					newValuesMap.getOrDefault(key, defaultValues),
					oldValuesMap.getOrDefault(key, defaultValues))) {

				continue;
			}

			attributes.add(new Attribute(key));
		}

		if (attributes.isEmpty()) {
			return null;
		}

		AuditMessage auditMessage = AuditMessageBuilder.buildAuditMessage(
			className, classPK, EventTypes.UPDATE, attributes);

		auditMessage.setCompanyId(companyId);

		return auditMessage;
	}

}