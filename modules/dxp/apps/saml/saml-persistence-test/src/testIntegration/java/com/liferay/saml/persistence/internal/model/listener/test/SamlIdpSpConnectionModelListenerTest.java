/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.saml.persistence.internal.model.listener.test;

import com.liferay.arquillian.extension.junit.bridge.junit.Arquillian;
import com.liferay.petra.lang.SafeCloseable;
import com.liferay.portal.configuration.test.util.ConfigurationTemporarySwapper;
import com.liferay.portal.kernel.audit.AuditMessage;
import com.liferay.portal.kernel.json.JSONObject;
import com.liferay.portal.kernel.json.JSONUtil;
import com.liferay.portal.kernel.model.Company;
import com.liferay.portal.kernel.security.auth.CompanyThreadLocal;
import com.liferay.portal.kernel.test.rule.AggregateTestRule;
import com.liferay.portal.kernel.test.rule.DeleteAfterTestRun;
import com.liferay.portal.kernel.test.util.CompanyTestUtil;
import com.liferay.portal.kernel.test.util.RandomTestUtil;
import com.liferay.portal.kernel.test.util.ServiceContextTestUtil;
import com.liferay.portal.kernel.test.util.TestPropsValues;
import com.liferay.portal.kernel.util.HashMapDictionaryBuilder;
import com.liferay.portal.security.audit.AuditMessageProcessor;
import com.liferay.portal.security.audit.event.generators.constants.EventTypes;
import com.liferay.portal.security.audit.router.configuration.LoggingAuditMessageProcessorConfiguration;
import com.liferay.portal.test.log.LogCapture;
import com.liferay.portal.test.log.LogEntry;
import com.liferay.portal.test.log.LoggerTestUtil;
import com.liferay.portal.test.rule.FeatureFlag;
import com.liferay.portal.test.rule.Inject;
import com.liferay.portal.test.rule.LiferayIntegrationTestRule;
import com.liferay.saml.persistence.model.SamlIdpSpConnection;
import com.liferay.saml.persistence.service.SamlIdpSpConnectionLocalService;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.ServiceRegistration;

import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;

/**
 * @author Lucas Miranda
 */
@RunWith(Arquillian.class)
public class SamlIdpSpConnectionModelListenerTest {

	@ClassRule
	@Rule
	public static final AggregateTestRule aggregateTestRule =
		new LiferayIntegrationTestRule();

	@Before
	public void setUp() throws Exception {
		Bundle bundle = FrameworkUtil.getBundle(getClass());

		BundleContext bundleContext = bundle.getBundleContext();

		_serviceRegistration = bundleContext.registerService(
			AuditMessageProcessor.class, _auditMessages::add,
			HashMapDictionaryBuilder.<String, Object>put(
				"eventTypes", "*"
			).build());
	}

	@After
	public void tearDown() throws Exception {
		_serviceRegistration.unregister();
	}

	@FeatureFlag("LPD-6417")
	@Test
	public void testOnAfterCreate() throws Exception {
		try (ConfigurationTemporarySwapper configurationTemporarySwapper =
				new ConfigurationTemporarySwapper(
					LoggingAuditMessageProcessorConfiguration.class.getName(),
					HashMapDictionaryBuilder.<String, Object>put(
						"enabled", true
					).put(
						"logMessageFormat", "JSON"
					).build());
			LogCapture logCapture = LoggerTestUtil.configureLog4JLogger(
				"com.liferay.portal.security.audit.router.internal." +
					"LoggingAuditMessageProcessor",
				LoggerTestUtil.INFO)) {

			String metadataXml = RandomTestUtil.randomString();

			_samlIdpSpConnection = _addSamlIdpSpConnection(metadataXml);

			AuditMessage auditMessage = _getAuditMessage(EventTypes.ADD);

			_assertAdditionalInfo(auditMessage, _samlIdpSpConnection);

			Assert.assertEquals(
				"instance.samlidpspconnection.add",
				auditMessage.getResourceAction());

			List<LogEntry> logEntries = logCapture.getLogEntries();

			Assert.assertEquals(logEntries.toString(), 1, logEntries.size());

			LogEntry logEntry = logEntries.get(0);

			String message = logEntry.getMessage();

			Assert.assertFalse(message.contains(metadataXml));

			JSONAssert.assertEquals(
				String.valueOf(auditMessage.toJSONObject()), message,
				JSONCompareMode.STRICT);
		}
	}

	@Test
	public void testOnBeforeRemove() throws Exception {
		String metadataXml = RandomTestUtil.randomString();

		SamlIdpSpConnection samlIdpSpConnection = _addSamlIdpSpConnection(
			metadataXml);

		_samlIdpSpConnectionLocalService.deleteSamlIdpSpConnection(
			samlIdpSpConnection.getSamlIdpSpConnectionId());

		AuditMessage auditMessage = _getAuditMessage(EventTypes.DELETE);

		_assertAdditionalInfo(auditMessage, samlIdpSpConnection);

		String json = String.valueOf(auditMessage.toJSONObject());

		Assert.assertFalse(json.contains(metadataXml));
	}

	@Test
	public void testOnBeforeUpdate() throws Exception {
		_company = CompanyTestUtil.addCompany();

		String metadataXml = RandomTestUtil.randomString();

		_samlIdpSpConnection = _addSamlIdpSpConnection(metadataXml);

		_auditMessages.clear();

		_samlIdpSpConnection =
			_samlIdpSpConnectionLocalService.updateSamlIdpSpConnection(
				_samlIdpSpConnection.getSamlIdpSpConnectionId(),
				_samlIdpSpConnection.getSamlSpEntityId(),
				_samlIdpSpConnection.getAssertionLifetime(),
				_samlIdpSpConnection.getAttributeNames(),
				_samlIdpSpConnection.isAttributesEnabled(),
				_samlIdpSpConnection.isAttributesNamespaceEnabled(),
				_samlIdpSpConnection.isEnabled(),
				_samlIdpSpConnection.isEncryptionForced(),
				_samlIdpSpConnection.getMetadataUrl(), null,
				_samlIdpSpConnection.getName(),
				_samlIdpSpConnection.getNameIdAttribute(),
				_samlIdpSpConnection.getNameIdFormat(),
				ServiceContextTestUtil.getServiceContext());

		Assert.assertTrue(_auditMessages.isEmpty());

		String newMetadataXml = RandomTestUtil.randomString();

		_samlIdpSpConnection.setMetadataXml(newMetadataXml);

		String name = _samlIdpSpConnection.getName();

		String newName = RandomTestUtil.randomString();

		_samlIdpSpConnection.setName(newName);

		try (SafeCloseable safeCloseable =
				CompanyThreadLocal.setCompanyIdWithSafeCloseable(
					_company.getCompanyId())) {

			_samlIdpSpConnection =
				_samlIdpSpConnectionLocalService.updateSamlIdpSpConnection(
					_samlIdpSpConnection);
		}

		AuditMessage auditMessage = _getAuditMessage(EventTypes.UPDATE);

		Assert.assertEquals(
			_samlIdpSpConnection.getCompanyId(), auditMessage.getCompanyId());

		JSONObject additionalInfoJSONObject = auditMessage.getAdditionalInfo();

		JSONAssert.assertEquals(
			JSONUtil.putAll(
				JSONUtil.put(
					"name", "metadataXml"
				).put(
					"newValue", ""
				).put(
					"oldValue", ""
				),
				JSONUtil.put(
					"name", "name"
				).put(
					"newValue", newName
				).put(
					"oldValue", name
				)
			).toString(),
			String.valueOf(additionalInfoJSONObject.getJSONArray("attributes")),
			JSONCompareMode.NON_EXTENSIBLE);

		String json = String.valueOf(auditMessage.toJSONObject());

		Assert.assertFalse(json.contains(metadataXml));
		Assert.assertFalse(json.contains(newMetadataXml));
	}

	private SamlIdpSpConnection _addSamlIdpSpConnection(String metadataXml)
		throws Exception {

		SamlIdpSpConnection samlIdpSpConnection =
			_samlIdpSpConnectionLocalService.createSamlIdpSpConnection(
				RandomTestUtil.nextLong());

		samlIdpSpConnection.setCompanyId(TestPropsValues.getCompanyId());
		samlIdpSpConnection.setSamlSpEntityId(RandomTestUtil.randomString());
		samlIdpSpConnection.setMetadataXml(metadataXml);
		samlIdpSpConnection.setName(RandomTestUtil.randomString());

		return _samlIdpSpConnectionLocalService.addSamlIdpSpConnection(
			samlIdpSpConnection);
	}

	private void _assertAdditionalInfo(
			AuditMessage auditMessage, SamlIdpSpConnection samlIdpSpConnection)
		throws Exception {

		Assert.assertEquals(
			samlIdpSpConnection.getCompanyId(), auditMessage.getCompanyId());

		JSONAssert.assertEquals(
			JSONUtil.put(
				"name", samlIdpSpConnection.getName()
			).put(
				"samlSpEntityId", samlIdpSpConnection.getSamlSpEntityId()
			).toString(),
			String.valueOf(auditMessage.getAdditionalInfo()),
			JSONCompareMode.STRICT);
	}

	private AuditMessage _getAuditMessage(String eventType) {
		for (AuditMessage auditMessage : _auditMessages) {
			if (Objects.equals(
					auditMessage.getClassName(),
					SamlIdpSpConnection.class.getName()) &&
				Objects.equals(auditMessage.getEventType(), eventType)) {

				return auditMessage;
			}
		}

		throw new AssertionError(
			"Audit message " + eventType + " was not found");
	}

	private final List<AuditMessage> _auditMessages =
		new CopyOnWriteArrayList<>();

	@DeleteAfterTestRun
	private Company _company;

	@DeleteAfterTestRun
	private SamlIdpSpConnection _samlIdpSpConnection;

	@Inject
	private SamlIdpSpConnectionLocalService _samlIdpSpConnectionLocalService;

	private ServiceRegistration<AuditMessageProcessor> _serviceRegistration;

}