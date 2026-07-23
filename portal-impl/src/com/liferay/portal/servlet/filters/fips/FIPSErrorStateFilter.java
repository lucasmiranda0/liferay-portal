/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.servlet.filters.fips;

import com.liferay.portal.kernel.security.fips.FIPSModeValidator;
import com.liferay.portal.servlet.filters.BasePortalFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.PrintWriter;

/**
 * @author Lucas Miranda
 */
public class FIPSErrorStateFilter extends BasePortalFilter {

	@Override
	protected void processFilter(
			HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, FilterChain filterChain)
		throws Exception {

		if (FIPSModeValidator.isInErrorState()) {
			httpServletResponse.setStatus(
				HttpServletResponse.SC_SERVICE_UNAVAILABLE);

			try (PrintWriter printWriter = httpServletResponse.getWriter()) {
				printWriter.println("The service is unavailable.");
			}

			return;
		}

		super.processFilter(
			httpServletRequest, httpServletResponse, filterChain);
	}

}