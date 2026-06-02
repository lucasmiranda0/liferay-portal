/**
 * SPDX-FileCopyrightText: (c) 2026 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.kernel.security.fips;

import com.liferay.petra.string.StringBundler;
import com.liferay.portal.kernel.util.PropsValues;
import com.liferay.portal.kernel.util.StringUtil;
import com.liferay.portal.kernel.util.Validator;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Centralizes FIPS 140-3 algorithm enforcement. When FIPS mode is enabled, the
 * <code>check*</code> methods reject any cryptographic algorithm or key size
 * that is not on the FIPS-approved allowlist before it can be handed to JCA.
 * When FIPS mode is disabled the methods are pass-through, preserving the
 * portal's existing behavior.
 *
 * @author Lucas Miranda
 */
public class FIPSUtil {

	/**
	 * The IV length, in bytes, used for AES/GCM. FIPS SP 800-38D recommends a
	 * 96-bit (12 byte) IV.
	 */
	public static final int GCM_IV_LENGTH = 12;

	/**
	 * The authentication tag length, in bits, used for AES/GCM.
	 */
	public static final int GCM_TAG_LENGTH_BITS = 128;

	/**
	 * The FIPS-approved cipher transformation replacing the default ECB mode.
	 */
	public static final String GCM_TRANSFORMATION = "AES/GCM/NoPadding";

	/**
	 * Validates a symmetric cipher algorithm against the FIPS allowlist. Returns
	 * the algorithm unchanged when FIPS mode is disabled or the algorithm is
	 * approved.
	 *
	 * @param  algorithm the JCA algorithm name (for example, <code>AES</code>)
	 * @return the validated algorithm
	 * @throws SecurityException if FIPS mode is enabled and the algorithm is not
	 *         approved
	 */
	public static String checkCipherAlgorithm(String algorithm) {
		if (!isEnabled()) {
			return algorithm;
		}

		String baseAlgorithm = _baseAlgorithm(algorithm);

		if (!_approvedCipherAlgorithms.contains(
				StringUtil.toUpperCase(baseAlgorithm))) {

			throw new SecurityException(
				"FIPS mode does not approve the cipher algorithm " + algorithm);
		}

		return algorithm;
	}

	/**
	 * Validates a message digest algorithm against the FIPS allowlist. Returns
	 * the algorithm unchanged when FIPS mode is disabled or the algorithm is
	 * approved.
	 *
	 * @param  algorithm the JCA digest algorithm name (for example,
	 *         <code>SHA-256</code>)
	 * @return the validated algorithm
	 * @throws SecurityException if FIPS mode is enabled and the algorithm is not
	 *         approved
	 */
	public static String checkDigestAlgorithm(String algorithm) {
		if (!isEnabled()) {
			return algorithm;
		}

		if (!_approvedDigestAlgorithms.contains(_normalizeDigest(algorithm))) {
			throw new SecurityException(
				"FIPS mode does not approve the message digest algorithm " +
					algorithm);
		}

		return algorithm;
	}

	/**
	 * Validates a symmetric key size against the FIPS allowlist. A no-op when
	 * FIPS mode is disabled.
	 *
	 * @param  algorithm the JCA algorithm name the key size applies to
	 * @param  keySizeBits the key size in bits
	 * @throws SecurityException if FIPS mode is enabled and the key size is not
	 *         approved
	 */
	public static void checkKeySize(String algorithm, int keySizeBits) {
		if (!isEnabled()) {
			return;
		}

		if (!_approvedKeySizes.contains(keySizeBits)) {
			throw new SecurityException(
				StringBundler.concat(
					"FIPS mode does not approve the key size ", keySizeBits,
					" for the algorithm ", algorithm));
		}
	}

	/**
	 * Returns whether FIPS mode is enabled, as configured by the
	 * <code>fips.enabled</code> portal property.
	 *
	 * @return <code>true</code> if FIPS mode is enabled
	 */
	public static boolean isEnabled() {
		return PropsValues.FIPS_ENABLED;
	}

	private static String _baseAlgorithm(String algorithm) {
		if (Validator.isNull(algorithm)) {
			return algorithm;
		}

		int index = algorithm.indexOf('/');

		if (index == -1) {
			return algorithm;
		}

		return algorithm.substring(0, index);
	}

	private static String _normalizeDigest(String algorithm) {
		if (Validator.isNull(algorithm)) {
			return algorithm;
		}

		String normalizedAlgorithm = StringUtil.toUpperCase(algorithm);

		normalizedAlgorithm = StringUtil.removeChar(normalizedAlgorithm, '-');

		return StringUtil.replace(normalizedAlgorithm, "SHA", "SHA-");
	}

	private static final Set<String> _approvedCipherAlgorithms = new HashSet<>(
		Arrays.asList("AES"));
	private static final Set<String> _approvedDigestAlgorithms = new HashSet<>(
		Arrays.asList("SHA-256", "SHA-384", "SHA-512"));
	private static final Set<Integer> _approvedKeySizes = new HashSet<>(
		Arrays.asList(128, 192, 256));

}