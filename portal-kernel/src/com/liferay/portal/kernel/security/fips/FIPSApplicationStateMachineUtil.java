/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.security.fips;

/**
 * @author Jorge García Jiménez
 */
public class FIPSApplicationStateMachineUtil {

	public static FIPSApplicationState getFIPSApplicationState() {
		return _fipsApplicationStateMachine.getFIPSApplicationState();
	}

	public static void selfTest(Runnable runnable) {
		transition(FIPSApplicationState.SELF_TEST);

		try {
			runnable.run();
		}
		catch (Throwable throwable) {
			transition(FIPSApplicationState.ERROR);

			throw throwable;
		}

		transition(FIPSApplicationState.OPERATIONAL);
	}

	public static void transition(FIPSApplicationState fipsApplicationState) {
		_fipsApplicationStateMachine.transition(fipsApplicationState);
	}

	public static FIPSApplicationState transitionOrGetBlockingState(
		FIPSApplicationState fipsApplicationState) {

		return _fipsApplicationStateMachine.transitionOrGetBlockingState(
			fipsApplicationState);
	}

	private static final FIPSApplicationStateMachine
		_fipsApplicationStateMachine = new FIPSApplicationStateMachine();

}