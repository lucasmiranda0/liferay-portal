/**
 * SPDX-FileCopyrightText: (c) 2000 Liferay, Inc. https://liferay.com
 * SPDX-License-Identifier: LGPL-2.1-or-later OR LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06
 */

package com.liferay.portal.encryptor;

import com.liferay.petra.string.StringPool;
import com.liferay.portal.kernel.encryptor.Encryptor;
import com.liferay.portal.kernel.encryptor.EncryptorException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.security.fips.FIPSUtil;
import com.liferay.portal.kernel.util.Base64;
import com.liferay.portal.kernel.util.DigesterUtil;
import com.liferay.portal.kernel.util.GetterUtil;
import com.liferay.portal.kernel.util.PropsKeys;
import com.liferay.portal.kernel.util.PropsUtil;
import com.liferay.portal.kernel.util.StringUtil;

import java.security.Key;
import java.security.SecureRandom;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.osgi.service.component.annotations.Component;

/**
 * @author Brian Wing Shun Chan
 * @author Shuyang Zhou
 * @author Mika Koivisto
 */
@Component(service = Encryptor.class)
public class EncryptorImpl implements Encryptor {

	public static final String ENCODING = DigesterUtil.ENCODING;

	public static final String KEY_ALGORITHM = StringUtil.toUpperCase(
		GetterUtil.getString(
			PropsUtil.get(PropsKeys.COMPANY_ENCRYPTION_ALGORITHM)));

	public static final int KEY_SIZE = GetterUtil.getInteger(
		PropsUtil.get(PropsKeys.COMPANY_ENCRYPTION_KEY_SIZE));

	@Override
	public String decrypt(Key key, String encryptedString)
		throws EncryptorException {

		byte[] encryptedBytes = Base64.decode(encryptedString);

		return _decryptUnencodedAsString(key, encryptedBytes);
	}

	@Override
	public byte[] decryptUnencodedAsBytes(Key key, byte[] encryptedBytes)
		throws EncryptorException {

		try {

			// When FIPS mode is enabled, ciphertext produced after the upgrade
			// is prefixed with a GCM IV. Attempt the GCM format first and fall
			// back to the legacy mode so values stored before FIPS was enabled
			// remain readable.

			if (FIPSUtil.isEnabled()) {
				try {
					return _decryptGCM(key, encryptedBytes);
				}
				catch (Exception exception) {
					if (_log.isDebugEnabled()) {
						_log.debug(
							"Falling back to legacy decryption after GCM " +
								"failure",
							exception);
					}
				}
			}

			return _decryptLegacy(key, encryptedBytes);
		}
		catch (Exception exception) {
			throw new EncryptorException(exception);
		}
	}

	@Override
	public Key deserializeKey(String base64String) {
		byte[] bytes = Base64.decode(base64String);

		return new SecretKeySpec(bytes, EncryptorImpl.KEY_ALGORITHM);
	}

	@Override
	public String encrypt(Key key, String plainText) throws EncryptorException {
		if (key == null) {
			if (_log.isWarnEnabled()) {
				_log.warn("Skip encrypting based on a null key");
			}

			return plainText;
		}

		byte[] encryptedBytes = encryptUnencoded(key, plainText);

		return Base64.encode(encryptedBytes);
	}

	@Override
	public byte[] encryptUnencoded(Key key, byte[] plainBytes)
		throws EncryptorException {

		try {
			if (FIPSUtil.isEnabled()) {
				return _encryptGCM(key, plainBytes);
			}

			String algorithm = key.getAlgorithm();

			String cacheKey = algorithm + StringPool.POUND + key.toString();

			Cipher cipher = _encryptCipherMap.get(cacheKey);

			if (cipher == null) {
				cipher = Cipher.getInstance(algorithm);

				cipher.init(Cipher.ENCRYPT_MODE, key);

				_encryptCipherMap.put(cacheKey, cipher);
			}

			synchronized (cipher) {
				return cipher.doFinal(plainBytes);
			}
		}
		catch (Exception exception) {
			throw new EncryptorException(exception);
		}
	}

	@Override
	public byte[] encryptUnencoded(Key key, String plainText)
		throws EncryptorException {

		try {
			byte[] decryptedBytes = plainText.getBytes(ENCODING);

			return encryptUnencoded(key, decryptedBytes);
		}
		catch (Exception exception) {
			throw new EncryptorException(exception);
		}
	}

	@Override
	public Key generateKey() throws EncryptorException {
		return _generateKey(KEY_ALGORITHM);
	}

	@Override
	public String serializeKey(Key key) {
		return Base64.encode(key.getEncoded());
	}

	private byte[] _decryptGCM(Key key, byte[] encryptedBytes)
		throws Exception {

		byte[] iv = Arrays.copyOfRange(
			encryptedBytes, 0, FIPSUtil.GCM_IV_LENGTH);
		byte[] cipherBytes = Arrays.copyOfRange(
			encryptedBytes, FIPSUtil.GCM_IV_LENGTH, encryptedBytes.length);

		Cipher cipher = Cipher.getInstance(FIPSUtil.GCM_TRANSFORMATION);

		cipher.init(
			Cipher.DECRYPT_MODE, key,
			new GCMParameterSpec(FIPSUtil.GCM_TAG_LENGTH_BITS, iv));

		return cipher.doFinal(cipherBytes);
	}

	private byte[] _decryptLegacy(Key key, byte[] encryptedBytes)
		throws Exception {

		String algorithm = key.getAlgorithm();

		String cacheKey = algorithm + StringPool.POUND + key.toString();

		Cipher cipher = _decryptCipherMap.get(cacheKey);

		if (cipher == null) {
			cipher = Cipher.getInstance(algorithm);

			cipher.init(Cipher.DECRYPT_MODE, key);

			_decryptCipherMap.put(cacheKey, cipher);
		}

		synchronized (cipher) {
			return cipher.doFinal(encryptedBytes);
		}
	}

	private String _decryptUnencodedAsString(Key key, byte[] encryptedBytes)
		throws EncryptorException {

		try {
			byte[] decryptedBytes = decryptUnencodedAsBytes(
				key, encryptedBytes);

			return new String(decryptedBytes, ENCODING);
		}
		catch (Exception exception) {
			throw new EncryptorException(exception);
		}
	}

	private byte[] _encryptGCM(Key key, byte[] plainBytes) throws Exception {
		byte[] iv = new byte[FIPSUtil.GCM_IV_LENGTH];

		SecureRandom secureRandom = _getSecureRandom();

		secureRandom.nextBytes(iv);

		Cipher cipher = Cipher.getInstance(FIPSUtil.GCM_TRANSFORMATION);

		cipher.init(
			Cipher.ENCRYPT_MODE, key,
			new GCMParameterSpec(FIPSUtil.GCM_TAG_LENGTH_BITS, iv));

		byte[] cipherBytes = cipher.doFinal(plainBytes);

		byte[] encryptedBytes = new byte[iv.length + cipherBytes.length];

		System.arraycopy(iv, 0, encryptedBytes, 0, iv.length);
		System.arraycopy(
			cipherBytes, 0, encryptedBytes, iv.length, cipherBytes.length);

		return encryptedBytes;
	}

	private Key _generateKey(String algorithm) throws EncryptorException {
		try {
			FIPSUtil.checkCipherAlgorithm(algorithm);
			FIPSUtil.checkKeySize(algorithm, KEY_SIZE);

			KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);

			keyGenerator.init(KEY_SIZE, _getSecureRandom());

			return keyGenerator.generateKey();
		}
		catch (Exception exception) {
			throw new EncryptorException(exception);
		}
	}

	private SecureRandom _getSecureRandom() throws Exception {
		if (FIPSUtil.isEnabled()) {
			return SecureRandom.getInstance("DEFAULT", "BCFIPS");
		}

		return new SecureRandom();
	}

	private static final Log _log = LogFactoryUtil.getLog(EncryptorImpl.class);

	private final Map<String, Cipher> _decryptCipherMap =
		new ConcurrentHashMap<>(1, 1F, 1);
	private final Map<String, Cipher> _encryptCipherMap =
		new ConcurrentHashMap<>(1, 1F, 1);

}