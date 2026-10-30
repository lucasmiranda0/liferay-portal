/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.saml.persistence.internal.model.listener;

import com.liferay.portal.kernel.audit.AuditMessage;
import com.liferay.portal.kernel.audit.AuditRouter;
import com.liferay.portal.kernel.exception.ModelListenerException;
import com.liferay.portal.kernel.json.JSONObject;
import com.liferay.portal.kernel.model.BaseModelListener;
import com.liferay.portal.kernel.model.ModelListener;
import com.liferay.portal.security.audit.event.generators.constants.EventTypes;
import com.liferay.portal.security.audit.event.generators.util.Attribute;
import com.liferay.portal.security.audit.event.generators.util.AttributesBuilder;
import com.liferay.portal.security.audit.event.generators.util.AuditMessageBuilder;
import com.liferay.saml.persistence.model.SamlSpIdpConnection;

import java.util.List;
import java.util.Objects;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * @author Lucas Miranda
 */
@Component(service = ModelListener.class)
public class SamlSpIdpConnectionModelListener
	extends BaseModelListener<SamlSpIdpConnection> {

	@Override
	public void onAfterCreate(SamlSpIdpConnection samlSpIdpConnection)
		throws ModelListenerException {

		_route(null, EventTypes.ADD, samlSpIdpConnection);
	}

	@Override
	public void onBeforeRemove(SamlSpIdpConnection samlSpIdpConnection)
		throws ModelListenerException {

		_route(null, EventTypes.DELETE, samlSpIdpConnection);
	}

	@Override
	public void onBeforeUpdate(
			SamlSpIdpConnection originalSamlSpIdpConnection,
			SamlSpIdpConnection samlSpIdpConnection)
		throws ModelListenerException {

		List<Attribute> attributes = _getModifiedAttributes(
			originalSamlSpIdpConnection, samlSpIdpConnection);

		if (!attributes.isEmpty()) {
			_route(attributes, EventTypes.UPDATE, samlSpIdpConnection);
		}
	}

	private List<Attribute> _getModifiedAttributes(
		SamlSpIdpConnection originalSamlSpIdpConnection,
		SamlSpIdpConnection samlSpIdpConnection) {

		AttributesBuilder attributesBuilder = new AttributesBuilder(
			samlSpIdpConnection, originalSamlSpIdpConnection);

		attributesBuilder.add("assertionSignatureRequired");
		attributesBuilder.add("clockSkew");
		attributesBuilder.add("enabled");
		attributesBuilder.add("forceAuthn");
		attributesBuilder.add("ldapImportEnabled");
		attributesBuilder.add("metadataUrl");
		attributesBuilder.add("name");
		attributesBuilder.add("nameIdFormat");
		attributesBuilder.add("samlIdpEntityId");
		attributesBuilder.add("signAuthnRequest");
		attributesBuilder.add("unknownUsersAreStrangers");
		attributesBuilder.add("userAttributeMappings");
		attributesBuilder.add("userIdentifierExpression");

		List<Attribute> attributes = attributesBuilder.getAttributes();

		if (!Objects.equals(
				originalSamlSpIdpConnection.getMetadataXml(),
				samlSpIdpConnection.getMetadataXml())) {

			attributes.add(new Attribute("metadataXml"));
		}

		return attributes;
	}

	private void _route(
			List<Attribute> attributes, String eventType,
			SamlSpIdpConnection samlSpIdpConnection)
		throws ModelListenerException {

		try {
			AuditMessage auditMessage = AuditMessageBuilder.buildAuditMessage(
				samlSpIdpConnection, eventType, attributes);

			JSONObject additionalInfoJSONObject =
				auditMessage.getAdditionalInfo();

			additionalInfoJSONObject.put(
				"name", samlSpIdpConnection.getName()
			).put(
				"samlIdpEntityId", samlSpIdpConnection.getSamlIdpEntityId()
			);

			auditMessage.setCompanyId(samlSpIdpConnection.getCompanyId());

			_auditRouter.route(auditMessage);
		}
		catch (Exception exception) {
			throw new ModelListenerException(exception);
		}
	}

	@Reference
	private AuditRouter _auditRouter;

}