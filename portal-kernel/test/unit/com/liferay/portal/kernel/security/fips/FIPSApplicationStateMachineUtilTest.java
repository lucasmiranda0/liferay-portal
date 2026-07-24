/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.security.fips;

import com.liferay.portal.kernel.test.ReflectionTestUtil;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Jorge García Jiménez
 */
public class FIPSApplicationStateMachineUtilTest {

	@Before
	public void setUp() {
		_resetFIPSApplicationState();
	}

	@Test
	public void testSelfTest() {
		FIPSApplicationStateMachineUtil.selfTest(
			() -> {
			});

		Assert.assertEquals(
			FIPSApplicationState.OPERATIONAL,
			FIPSApplicationStateMachineUtil.getFIPSApplicationState());
	}

	@Test
	public void testSelfTestLatchesErrorOnFailure() {
		_testSelfTestLatchesErrorOnFailure(new RuntimeException());
		_testSelfTestLatchesErrorOnFailure(new SecurityException());
	}

	@Test
	public void testTransition() {
		Assert.assertEquals(
			FIPSApplicationState.INITIALIZING,
			FIPSApplicationStateMachineUtil.getFIPSApplicationState());

		FIPSApplicationStateMachineUtil.transition(
			FIPSApplicationState.SELF_TEST);

		Assert.assertEquals(
			FIPSApplicationState.SELF_TEST,
			FIPSApplicationStateMachineUtil.getFIPSApplicationState());

		FIPSApplicationStateMachineUtil.transition(
			FIPSApplicationState.OPERATIONAL);

		Assert.assertEquals(
			FIPSApplicationState.OPERATIONAL,
			FIPSApplicationStateMachineUtil.getFIPSApplicationState());
	}

	private void _resetFIPSApplicationState() {
		FIPSApplicationStateMachine fipsApplicationStateMachine =
			ReflectionTestUtil.getFieldValue(
				FIPSApplicationStateMachineUtil.class,
				"_fipsApplicationStateMachine");

		ReflectionTestUtil.setFieldValue(
			fipsApplicationStateMachine, "_fipsApplicationState",
			FIPSApplicationState.INITIALIZING);
	}

	private void _testSelfTestLatchesErrorOnFailure(
		RuntimeException runtimeException) {

		_resetFIPSApplicationState();

		Assert.assertThrows(
			runtimeException.getClass(),
			() -> FIPSApplicationStateMachineUtil.selfTest(
				() -> {
					throw runtimeException;
				}));

		Assert.assertEquals(
			FIPSApplicationState.ERROR,
			FIPSApplicationStateMachineUtil.getFIPSApplicationState());
	}

}