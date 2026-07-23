/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.servlet.filters.fips;

import com.liferay.portal.kernel.security.fips.FIPSModeValidator;
import com.liferay.portal.kernel.test.ReflectionTestUtil;
import com.liferay.portal.kernel.util.ProxyFactory;
import com.liferay.portal.test.rule.LiferayUnitTestRule;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.junit.After;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.mockito.Mockito;

/**
 * @author Lucas Miranda
 */
public class FIPSErrorStateFilterTest {

	@ClassRule
	@Rule
	public static final LiferayUnitTestRule liferayUnitTestRule =
		LiferayUnitTestRule.INSTANCE;

	@After
	public void tearDown() {
		ReflectionTestUtil.setFieldValue(
			FIPSModeValidator.class, "_fipsErrorState", false);
	}

	@Test
	public void testProcessFilterHaltsWhenInErrorState() throws Exception {
		ReflectionTestUtil.setFieldValue(
			FIPSModeValidator.class, "_fipsErrorState", true);

		FIPSErrorStateFilter fipsErrorStateFilter = new FIPSErrorStateFilter();

		HttpServletResponse httpServletResponse = Mockito.mock(
			HttpServletResponse.class);

		Mockito.when(
			httpServletResponse.getWriter()
		).thenReturn(
			new PrintWriter(new StringWriter())
		);

		FilterChain filterChain = Mockito.mock(FilterChain.class);

		fipsErrorStateFilter.processFilter(
			ProxyFactory.newDummyInstance(HttpServletRequest.class),
			httpServletResponse, filterChain);

		Mockito.verify(
			httpServletResponse
		).setStatus(
			HttpServletResponse.SC_SERVICE_UNAVAILABLE
		);

		Mockito.verify(
			filterChain, Mockito.never()
		).doFilter(
			Mockito.any(), Mockito.any()
		);
	}

	@Test
	public void testProcessFilterProceedsWhenNotInErrorState()
		throws Exception {

		FIPSErrorStateFilter fipsErrorStateFilter = new FIPSErrorStateFilter();

		HttpServletResponse httpServletResponse = Mockito.mock(
			HttpServletResponse.class);

		FilterChain filterChain = Mockito.mock(FilterChain.class);

		fipsErrorStateFilter.processFilter(
			ProxyFactory.newDummyInstance(HttpServletRequest.class),
			httpServletResponse, filterChain);

		Mockito.verify(
			filterChain
		).doFilter(
			Mockito.any(), Mockito.any()
		);

		Mockito.verify(
			httpServletResponse, Mockito.never()
		).setStatus(
			Mockito.anyInt()
		);
	}

}