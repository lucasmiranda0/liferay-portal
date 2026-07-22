/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.security.fips.rest.internal.resource.v1_0;

import com.liferay.portal.kernel.audit.AuditMessage;
import com.liferay.portal.kernel.audit.AuditRouter;
import com.liferay.portal.kernel.json.JSONFactory;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.security.auth.PrincipalException;
import com.liferay.portal.kernel.security.fips.FIPSHealthCheckResult;
import com.liferay.portal.kernel.security.fips.FIPSModeValidator;
import com.liferay.portal.kernel.security.permission.PermissionChecker;
import com.liferay.portal.kernel.security.permission.PermissionThreadLocal;
import com.liferay.portal.kernel.service.RoleLocalService;
import com.liferay.portal.security.fips.rest.dto.v1_0.HealthVerification;
import com.liferay.portal.security.fips.rest.internal.audit.FIPSHealthAuditMessageBuilder;
import com.liferay.portal.security.fips.rest.internal.constants.FIPSActionKeys;
import com.liferay.portal.security.fips.rest.resource.v1_0.HealthVerificationResource;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import java.util.Date;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ServiceScope;

/**
 * @author Lucas Miranda
 */
@Component(
	properties = "OSGI-INF/liferay/rest/v1_0/health-verification.properties",
	scope = ServiceScope.PROTOTYPE, service = HealthVerificationResource.class
)
public class HealthVerificationResourceImpl
	extends BaseHealthVerificationResourceImpl {

	@Override
	public HealthVerification postHealthVerification() throws Exception {
		PermissionChecker permissionChecker =
			PermissionThreadLocal.getPermissionChecker();

		if (!permissionChecker.isOmniadmin() &&
			!_roleLocalService.hasUserRole(
				permissionChecker.getUserId(), permissionChecker.getCompanyId(),
				FIPSActionKeys.CRYPTO_OFFICER_ROLE_NAME, true)) {

			throw new PrincipalException.MustHavePermission(
				permissionChecker, FIPSActionKeys.TRIGGER_HEALTH_VERIFICATION);
		}

		FIPSHealthCheckResult result = FIPSModeValidator.runSelfTests();

		HealthVerification healthVerification = _toHealthVerification(result);

		if (result.getStatus() == FIPSHealthCheckResult.Status.NOT_APPLICABLE) {
			throw new WebApplicationException(
				Response.status(
					Response.Status.CONFLICT
				).entity(
					healthVerification
				).build());
		}

		if (result.getStatus() == FIPSHealthCheckResult.Status.FAILED) {
			_routeAuditMessage(result);

			throw new WebApplicationException(
				Response.status(
					Response.Status.SERVICE_UNAVAILABLE
				).entity(
					healthVerification
				).build());
		}

		return healthVerification;
	}

	private void _routeAuditMessage(FIPSHealthCheckResult result) {
		try {
			AuditMessage auditMessage = FIPSHealthAuditMessageBuilder.build(
				contextCompany.getCompanyId(), contextUser.getUserId(),
				contextUser.getFullName(), result, _jsonFactory);

			_auditRouter.route(auditMessage);
		}
		catch (Exception exception) {
			_log.error(
				"Unable to route periodic-health-failure audit message",
				exception);
		}
	}

	private HealthVerification _toHealthVerification(
		FIPSHealthCheckResult result) {

		HealthVerification healthVerification = new HealthVerification();

		healthVerification.setDate(() -> new Date());
		healthVerification.setFailedTest(result::getFailedTest);
		healthVerification.setFipsState(result::getFipsState);
		healthVerification.setProviderMessage(result::getProviderMessage);
		healthVerification.setProviderName(result::getProviderName);
		healthVerification.setStatus(
			() -> HealthVerification.Status.create(
				result.getStatus(
				).name()));

		return healthVerification;
	}

	private static final Log _log = LogFactoryUtil.getLog(
		HealthVerificationResourceImpl.class);

	@Reference
	private AuditRouter _auditRouter;

	@Reference
	private JSONFactory _jsonFactory;

	@Reference
	private RoleLocalService _roleLocalService;

}