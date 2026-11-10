/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.audit.router.internal.test;

import com.liferay.arquillian.extension.junit.bridge.junit.Arquillian;
import com.liferay.petra.lang.SafeCloseable;
import com.liferay.portal.configuration.persistence.ConfigurationOverridePropertiesUtil;
import com.liferay.portal.kernel.audit.AuditMessage;
import com.liferay.portal.kernel.audit.AuditRequestContext;
import com.liferay.portal.kernel.audit.AuditRequestContextThreadLocal;
import com.liferay.portal.kernel.audit.AuditRouter;
import com.liferay.portal.kernel.json.JSONFactoryUtil;
import com.liferay.portal.kernel.json.JSONObject;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.test.ReflectionTestUtil;
import com.liferay.portal.kernel.test.rule.AggregateTestRule;
import com.liferay.portal.kernel.test.util.RandomTestUtil;
import com.liferay.portal.kernel.test.util.TestPropsValues;
import com.liferay.portal.kernel.util.HashMapBuilder;
import com.liferay.portal.security.audit.event.generators.constants.EventTypes;
import com.liferay.portal.security.audit.event.generators.util.AuditMessageBuilder;
import com.liferay.portal.security.audit.router.configuration.LoggingAuditMessageProcessorConfiguration;
import com.liferay.portal.test.log.LogCapture;
import com.liferay.portal.test.log.LogEntry;
import com.liferay.portal.test.log.LoggerTestUtil;
import com.liferay.portal.test.rule.FeatureFlag;
import com.liferay.portal.test.rule.Inject;
import com.liferay.portal.test.rule.LiferayIntegrationTestRule;

import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.osgi.framework.FrameworkUtil;
import org.osgi.service.component.runtime.ServiceComponentRuntime;
import org.osgi.service.component.runtime.dto.ComponentDescriptionDTO;
import org.osgi.util.promise.Promise;

/**
 * @author Lucas Miranda
 */
@RunWith(Arquillian.class)
public class LoggingAuditMessageProcessorTest {

	@ClassRule
	@Rule
	public static final AggregateTestRule aggregateTestRule =
		new LiferayIntegrationTestRule();

	@FeatureFlag("LPD-6417")
	@Test
	public void testProcess() throws Exception {
		Log log = LogFactoryUtil.getLog(
			_CLASS_NAME_LOGGING_AUDIT_MESSAGE_PROCESSOR);

		Assert.assertTrue(log.isInfoEnabled());

		Map<String, Map<String, Object>> overridePropertiesMap =
			ReflectionTestUtil.getFieldValue(
				ConfigurationOverridePropertiesUtil.getOverridePropertiesMap(),
				"m");

		Map<String, Object> overrideProperties = overridePropertiesMap.put(
			LoggingAuditMessageProcessorConfiguration.class.getName(),
			HashMapBuilder.<String, Object>put(
				"enabled", true
			).put(
				"logMessageFormat", "JSON"
			).build());

		AuditRequestContext auditRequestContext = new AuditRequestContext();

		auditRequestContext.setRealUserId(TestPropsValues.getUserId());

		try (LogCapture logCapture = LoggerTestUtil.configureLog4JLogger(
				_CLASS_NAME_LOGGING_AUDIT_MESSAGE_PROCESSOR,
				LoggerTestUtil.INFO);
			SafeCloseable safeCloseable =
				AuditRequestContextThreadLocal.
					setAuditRequestContextWithSafeCloseable(
						auditRequestContext)) {

			_reactivateLoggingAuditMessageProcessor();

			long classPK = RandomTestUtil.randomLong();

			AuditMessage auditMessage = AuditMessageBuilder.buildAuditMessage(
				0, 0, User.class.getName(), classPK, null, EventTypes.ADD,
				null);

			_auditRouter.route(auditMessage);

			List<LogEntry> logEntries = logCapture.getLogEntries();

			Assert.assertEquals(logEntries.toString(), 1, logEntries.size());

			LogEntry logEntry = logEntries.get(0);

			JSONObject jsonObject = JSONFactoryUtil.createJSONObject(
				logEntry.getMessage());

			Assert.assertEquals(
				User.class.getName(), jsonObject.getString("className"));
			Assert.assertEquals(
				String.valueOf(classPK), jsonObject.getString("classPK"));
			Assert.assertEquals(
				TestPropsValues.getCompanyId(),
				jsonObject.getLong("companyId"));
			Assert.assertEquals(
				EventTypes.ADD, jsonObject.getString("eventType"));
			Assert.assertEquals(
				"instance.user.add", jsonObject.getString("resourceAction"));
			Assert.assertEquals("user", jsonObject.getString("resourceType"));

			User user = TestPropsValues.getUser();

			Assert.assertEquals(user.getUserId(), jsonObject.getLong("userId"));
			Assert.assertEquals(
				user.getFullName(), jsonObject.getString("userName"));
		}
		finally {
			if (overrideProperties == null) {
				overridePropertiesMap.remove(
					LoggingAuditMessageProcessorConfiguration.class.getName());
			}
			else {
				overridePropertiesMap.put(
					LoggingAuditMessageProcessorConfiguration.class.getName(),
					overrideProperties);
			}

			_reactivateLoggingAuditMessageProcessor();
		}
	}

	private void _reactivateLoggingAuditMessageProcessor() throws Exception {
		ComponentDescriptionDTO componentDescriptionDTO =
			_serviceComponentRuntime.getComponentDescriptionDTO(
				FrameworkUtil.getBundle(_auditRouter.getClass()),
				_CLASS_NAME_LOGGING_AUDIT_MESSAGE_PROCESSOR);

		Promise<Void> promise = _serviceComponentRuntime.disableComponent(
			componentDescriptionDTO);

		promise.getValue();

		promise = _serviceComponentRuntime.enableComponent(
			componentDescriptionDTO);

		promise.getValue();
	}

	private static final String _CLASS_NAME_LOGGING_AUDIT_MESSAGE_PROCESSOR =
		"com.liferay.portal.security.audit.router.internal." +
			"LoggingAuditMessageProcessor";

	@Inject
	private AuditRouter _auditRouter;

	@Inject
	private ServiceComponentRuntime _serviceComponentRuntime;

}