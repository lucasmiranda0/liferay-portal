/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.security.fips;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Jorge García Jiménez
 */
public class FIPSApplicationStateMachineTest {

	@Test
	public void testAllowedTransitions() {
		FIPSApplicationStateMachine fipsApplicationStateMachine =
			new FIPSApplicationStateMachine();

		Assert.assertEquals(
			FIPSApplicationState.INITIALIZING,
			fipsApplicationStateMachine.getFIPSApplicationState());

		_assertAllowedTransition(
			fipsApplicationStateMachine, FIPSApplicationState.SELF_TEST);
		_assertAllowedTransition(
			fipsApplicationStateMachine, FIPSApplicationState.OPERATIONAL);
		_assertAllowedTransition(
			fipsApplicationStateMachine, FIPSApplicationState.ERROR);
		_assertAllowedTransition(
			fipsApplicationStateMachine, FIPSApplicationState.POWER_OFF);
	}

	@Test
	public void testIllegalTransitions() {
		_assertIllegalTransition(
			FIPSApplicationState.INITIALIZING,
			FIPSApplicationState.OPERATIONAL);
		_assertIllegalTransition(
			FIPSApplicationState.OPERATIONAL,
			FIPSApplicationState.INITIALIZING);
		_assertIllegalTransition(
			FIPSApplicationState.OPERATIONAL, FIPSApplicationState.SELF_TEST);
	}

	@Test
	public void testTerminalStates() {
		for (FIPSApplicationState fipsApplicationState :
				FIPSApplicationState.values()) {

			if (fipsApplicationState != FIPSApplicationState.POWER_OFF) {
				_assertIllegalTransition(
					FIPSApplicationState.ERROR, fipsApplicationState);
			}

			_assertIllegalTransition(
				FIPSApplicationState.POWER_OFF, fipsApplicationState);
		}
	}

	private void _assertAllowedTransition(
		FIPSApplicationStateMachine fipsApplicationStateMachine,
		FIPSApplicationState fipsApplicationState) {

		fipsApplicationStateMachine.transition(fipsApplicationState);

		Assert.assertEquals(
			fipsApplicationState,
			fipsApplicationStateMachine.getFIPSApplicationState());
	}

	private void _assertIllegalTransition(
		FIPSApplicationState fromFIPSApplicationState,
		FIPSApplicationState toFIPSApplicationState) {

		FIPSApplicationStateMachine fipsApplicationStateMachine =
			_createFIPSApplicationStateMachine(fromFIPSApplicationState);

		Assert.assertThrows(
			IllegalStateException.class,
			() -> fipsApplicationStateMachine.transition(
				toFIPSApplicationState));

		Assert.assertEquals(
			fromFIPSApplicationState,
			fipsApplicationStateMachine.getFIPSApplicationState());
	}

	private FIPSApplicationStateMachine _createFIPSApplicationStateMachine(
		FIPSApplicationState fipsApplicationState) {

		FIPSApplicationStateMachine fipsApplicationStateMachine =
			new FIPSApplicationStateMachine();

		if (fipsApplicationState == FIPSApplicationState.INITIALIZING) {
			return fipsApplicationStateMachine;
		}

		if ((fipsApplicationState == FIPSApplicationState.ERROR) ||
			(fipsApplicationState == FIPSApplicationState.POWER_OFF) ||
			(fipsApplicationState == FIPSApplicationState.SELF_TEST)) {

			fipsApplicationStateMachine.transition(fipsApplicationState);

			return fipsApplicationStateMachine;
		}

		fipsApplicationStateMachine.transition(FIPSApplicationState.SELF_TEST);
		fipsApplicationStateMachine.transition(
			FIPSApplicationState.OPERATIONAL);

		return fipsApplicationStateMachine;
	}

}