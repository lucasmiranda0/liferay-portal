package com.liferay.portal.security.password.encryptor.internal;

import com.liferay.portal.kernel.exception.PwdEncryptorException;
import com.liferay.portal.kernel.security.SecureRandom;
import com.liferay.portal.kernel.security.pwd.PasswordEncryptor;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import org.osgi.service.component.annotations.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * @author Lucas Miranda
 */
@Component(
	property = "type=" + PasswordEncryptor.TYPE_ARGON2ID,
	service = PasswordEncryptor.class
)
public class Argon2idPasswordEncryptor implements PasswordEncryptor {

	@Override
	public String encrypt(
			String algorithm, String plainTextPassword,
			String encryptedPassword, boolean upgradeHashSecurity)
		throws PwdEncryptorException {



		if (upgradeHashSecurity) {
			encryptedPassword = null;
		}


		return "";
	}

	public static void encypt() {
		// uses Bouncy Castle
		System.out.println("Generate a 32 byte long encryption key with Argon2id");

		String password = "secret password";
		System.out.println("password: " + password);

		byte[] salt = generateSalt16Byte();
		System.out.println("salt (Base64): " + base64Encoding(salt));

		String encryptionKeyArgon2id = base64Encoding(generateArgon2idInteractive(password, salt));
		System.out.println("encryptionKeyArgon2id (Base64) interactive: " + encryptionKeyArgon2id);
	}

	public static byte[] generateArgon2idInteractive(String password, byte[] salt) {
		int iteration = 3;
		int memory = 66536;
		int outputLength = 32;
		int parallelism = 1;

		Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
			.withVersion(Argon2Parameters.ARGON2_VERSION_13)
			.withIterations(iteration)
			.withMemoryAsKB(memory)
			.withParallelism(parallelism)
			.withSalt(salt);

		Argon2BytesGenerator gen = new Argon2BytesGenerator();

		gen.init(builder.build());

		byte[] result = new byte[outputLength];

		gen.generateBytes(password.getBytes(StandardCharsets.UTF_8), result, 0, result.length);
		return result;
	}

	private static byte[] generateSalt16Byte() {
		SecureRandom secureRandom = new SecureRandom();
		byte[] salt = new byte[16];
		secureRandom.nextBytes(salt);
		return salt;
	}

	private static String base64Encoding(byte[] input) {
		return Base64.getEncoder().encodeToString(input);
	}
}
