package se.embuc.nano2fa;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

/**
 * Implementation of the Time-based One-Time Password (TOTP) two factor authentication algorithm. You need to:
 *
 * <ol>
 * <li>Use generateBase32Secret() to generate a secret key for a user.</li>
 * <li>Store the secret key in the database associated with the user account.</li>
 * <li>Display the QR image URL returned by qrImageUrl(...) to the user.</li>
 * <li>User uses the image to load the secret key into his authenticator application.</li>
 * </ol>
 *
 * <p>
 * Whenever the user logs in:
 * </p>
 *
 * <ol>
 * <li>The user enters the number from the authenticator application into the login form.</li>
 * <li>Read the secret associated with the user account from the database.</li>
 * <li>The server compares the user input with the output from generateCurrentNumber(...).</li>
 * <li>If they are equal then the user is allowed to log in.</li>
 * </ol>
 *
 * <p>
 * For more details about this magic algorithm, see: http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm
 * and more comprehensive: https://tools.ietf.org/html/rfc6238
 * </p>
 * <p>
 * The private key in TOTP should be a 20-byte (160-bit) secret. The private key is used with HMAC-SHA1 to encode the
 * epoch time counter. A token is extracted from the genetated 160-bit HMAC.
 * </p>
 * <p>
 * One important and simple reason why Base32 is used is that it uses A-Z uppercase only (no lowercase) and the numbers
 * 2-7. No 0189. 26 + 6 chars = 32. There are no lowercase letters and no digits 0189 so "i" "l" "I" and "1" are not
 * confused. There is only I. Confusion between B and 8, and 0 and O is also eliminated.
 * </p>
 *
 * @author graywatson
 * @author Emir Bucalovic
 * @since 09 Jun 2015
 */
public class TimeBasedOneTimePasswordUtil {

	private static final int RECOVER_CODE_CHUNK_DEFAULT_LENGTH = 4;
	private static final String HMAC_SHA1 = "HmacSHA1";
	protected static final int DEFAULT_PRIVATE_KEY_LENGTH = 20;
	/** default time-step which is part of the spec, 30 seconds is default */
	protected static final int DEFAULT_TIME_STEP_SECONDS = 30;
	/** default number of digits in a OTP string */
	protected static final int DEFAULT_OTP_LENGTH = 6;
	/** default hight/width of QR image */
	protected static final int DEFAULT_QR_DIMENSION = 200;
	/** set to the number of digits to control 0 prefix, set to 0 for no prefix */
	private static final int MAX_NUM_DIGITS_OUTPUT = 100;

	private static final String BLOCK_OF_ZEROS;
	private static final Base32 BASE32 = new Base32();
	//	Default server for generating images, might be also something like: "image-charts.com";
	private static final String SERVER_URI = "quickchart.io";

	/** Default number of milliseconds that they are allowed to be off and still match. (10 seconds) */
	private static final long DEFAULT_VALIDATION_WINDOW_MILLIS = 10_000;


	static {
		char[] chars = new char[MAX_NUM_DIGITS_OUTPUT];
		Arrays.fill(chars, '0');
		BLOCK_OF_ZEROS = new String(chars);
	}

	private TimeBasedOneTimePasswordUtil() {
		/** This is an utility class and it is not supposed to be instantiated. */
	}

	/**
	 * Generate and return a 16-character secret key in base32 format (A-Z2-7) using {@link SecureRandom}. Could be used to
	 * generate the QR image to be shared with the user. Other lengths should use {@link #generateBase32Secret(int)}.
	 *
	 * @return generated String
	 */
	public static String generateBase32Secret() {
		return generateBase32Secret(DEFAULT_PRIVATE_KEY_LENGTH);
	}

	/**
	 * Similar to {@link #generateBase32Secret()} but specifies a character length.
	 *
	 * @param numberOfDigits number of digits to generate
	 * @return generated String
	 */
	public static String generateBase32Secret(int numberOfDigits) {
		StringBuilder sb = new StringBuilder(numberOfDigits);
		Random random = new SecureRandom();
		for (int i = 0; i < numberOfDigits; i++) {
			int val = random.nextInt(32);
			if (val < 26) {
				sb.append((char) ('A' + val));
			} else {
				sb.append((char) ('2' + (val - 26)));
			}
		}
		return sb.toString();
	}

	/**
	 * Return the current number to be checked. This can be compared against user input.
	 *
	 * <p>
	 * WARNING: This requires a system clock that is in sync with the world.
	 * </p>
	 *
	 * @param base32Secret Secret string encoded using base-32 that was used to generate the QR code or shared with the
	 * user.
	 * @return A number as a string with possible leading zeros which should match the user's authenticator application
	 * output.
	 */
	public static String generateCurrentNumberString(String base32Secret) {
		return generateNumberString(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS, DEFAULT_OTP_LENGTH);
	}

	/**
	 * Return the QR image url thanks to Google. This can be shown to the user and scanned by the authenticator program as
	 * an easy way to enter the secret.
	 *
	 * @param keyId Name of the key that you want to show up in the users authentication application. Should already be URL
	 * encoded.
	 * @param secret Secret string that will be used when generating the current number.
	 * @return image url
	 */
	public static String qrImageUrl(String keyId, String secret) {
		return qrImageUrl(keyId, secret, DEFAULT_OTP_LENGTH, DEFAULT_QR_DIMENSION);
	}

	/**
	 * Return the QR image url thanks to Google. This can be shown to the user and scanned by the authenticator program as
	 * an easy way to enter the secret.
	 *
	 * @param keyId Name of the key that you want to show up in the users authentication application. Should already be URL
	 * encoded.
	 * @param secret Secret string that will be used when generating the current number.
	 * @param numDigits The number of digits of the OTP.
	 * @return image url
	 */
	public static String qrImageUrl(String keyId, String secret, int numDigits) {
		return qrImageUrl(keyId, secret, numDigits, DEFAULT_QR_DIMENSION);
	}

	/**
	 * Validate a given secret-number using the secret base-32 string. Uses default 10 second window to account for people
	 * being close to the end of the time-step.
	 *
	 * <p>
	 * WARNING: This requires a system clock that is in sync with the world.
	 * </p>
	 *
	 * @param base32Secret Secret string encoded using base-32 that was used to generate the QR code or shared with the
	 * user.
	 * @param authNumber Time based number provided by the user from their authenticator application.
	 * @return True if the authNumber matched the calculated number within the specified window.
	 */
	public static boolean validateCurrentNumber(String base32Secret, int authNumber) {
		return validateCurrentNumber(base32Secret, authNumber, DEFAULT_VALIDATION_WINDOW_MILLIS);
	}

	/**
	 * Validate a given secret-number using the secret base-32 string. This allows you to set a window in milliseconds to
	 * account for people being close to the end of the time-step. For example, if windowMillis is 10000 then this method
	 * will check the authNumber against the generated number from 10 seconds before now through 10 seconds after now.
	 *
	 * <p>
	 * WARNING: This requires a system clock that is in sync with the world.
	 * </p>
	 *
	 * @param base32Secret Secret string encoded using base-32 that was used to generate the QR code or shared with the
	 * user.
	 * @param authNumber Time based number provided by the user from their authenticator application.
	 * @param windowMillis Number of milliseconds that they are allowed to be off and still match. This checks before and
	 * after the current time to account for clock variance. Set to 0 for no window.
	 * @return True if the authNumber matched the calculated number within the specified window.
	 */
	public static boolean validateCurrentNumber(String base32Secret, int authNumber, long windowMillis) {
		return validateCurrentNumber(base32Secret, authNumber, windowMillis, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS, DEFAULT_OTP_LENGTH);
	}

	/**
	 * Generate formatted recovery code containing 20 base32 characters grouped in five (5) chunks of four (4) digits and
	 * separated by dash.
	 *
	 * @return the string
	 */
	public static String generateFormattedRecoveryCode() {
		StringBuilder builder = new StringBuilder();
		builder.append(generateBase32Secret(RECOVER_CODE_CHUNK_DEFAULT_LENGTH));
		builder.append('-');
		builder.append(generateBase32Secret(RECOVER_CODE_CHUNK_DEFAULT_LENGTH));
		builder.append('-');
		builder.append(generateBase32Secret(RECOVER_CODE_CHUNK_DEFAULT_LENGTH));
		builder.append('-');
		builder.append(generateBase32Secret(RECOVER_CODE_CHUNK_DEFAULT_LENGTH));
		builder.append('-');
		builder.append(generateBase32Secret(RECOVER_CODE_CHUNK_DEFAULT_LENGTH));
		return builder.toString();
	}

	/**
	 * Similar to {@link #generateNumberString(String, long, int, int)} but this returns a int instead of a string.
	 *
	 * @return A number which should match the user's authenticator application output.
	 */
	protected static int generateNumber(String base32Secret, long timeMillis, int timeStepSeconds) {
		return generateNumber(base32Secret, timeMillis, timeStepSeconds, DEFAULT_OTP_LENGTH);
	}

	/**
	 * Similar to {@link #generateNumberString(String, long, int, int)} but this returns a int instead of a string.
	 *
	 * @return A number which should match the user's authenticator application output.
	 */
	protected static int generateNumber(String base32Secret, long timeMillis, int timeStepSeconds, int numDigits) {
		long value = generateValue(timeMillis, timeStepSeconds);
		byte[] key = BASE32.decode(base32Secret);
		return generateNumberFromKeyValue(key, value, numDigits);
	}

	protected static int generateNumberFromKeyValue(byte[] key, long value, int numDigits) {
		try {
			byte[] data = new byte[8];
			for (int i = 7; value > 0; i--) {
				data[i] = (byte) (value & 0xFF);
				value >>= 8;
			}

			/* Encrypt the data with the key and return the SHA1 of it in hex */
			SecretKeySpec signKey = new SecretKeySpec(key, HMAC_SHA1);

			/*
			 * This will never throw. Every implementation of the Java platform is required to support at least: HmacMD5, HmacSHA1,
			 * HmacSHA256.
			 */
			Mac mac = Mac.getInstance(HMAC_SHA1);
			mac.init(signKey);
			byte[] hash = mac.doFinal(data);
			/* take the 4 least significant bits from the encrypted string as an offset */
			int offset = hash[hash.length - 1] & 0xF;

			long truncatedHash = 0;
			for (int i = offset; i < offset + 4; ++i) {
				truncatedHash <<= 8;
				// get the 4 bytes at the offset
				truncatedHash |= (hash[i] & 0xFF);
			}
			// cut off the top bit
			truncatedHash &= 0x7FFFFFFF;

			// the token is then the last <length> digits in the number
			long mask = 1;
			for (int i = 0; i < numDigits; i++) {
				mask *= 10;
			}
			truncatedHash %= mask;
			return (int) truncatedHash;
		} catch (GeneralSecurityException e) {
			/**
			 * <code>Mac.getInstance(HMAC_SHA1);</code> This will never throw. Every implementation of the Java platform is required to support
			 * at least: HmacMD5, HmacSHA1, HmacSHA256.
			 *
			 * <code>new SecretKeySpec(key, HMAC_SHA1)</code> will throw IllegalArgumentException if key is invalid
			 * (null or empty). But for sake of transparency, expose any underlying exception.
			 */
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Similar to {@link #generateCurrentNumberString(String)} except exposes other parameters. Mostly for testing.
	 */
	protected static String generateNumberString(String base32Secret, long timeMillis, int timeStepSeconds, int numDigits) {
		int number = generateNumber(base32Secret, timeMillis, timeStepSeconds, numDigits);
		return zeroPrepend(number, numDigits);
	}

	/**
	 * Return the otp-auth part of the QR image which is suitable to be injected into other QR generators (e.g. JS
	 * generator).
	 *
	 * @param keyId Name of the key that you want to show up in the users authentication application. Should already be URL
	 * encoded.
	 * @param secret Secret string that will be used when generating the current number.
	 */
	protected static String generateOtpAuthUrl(String keyId, String secret) {
		return generateOtpAuthUrl(keyId, secret, DEFAULT_OTP_LENGTH);
	}

	/**
	 * Return the otp-auth part of the QR image which is suitable to be injected into other QR generators (e.g. JS
	 * generator).
	 *
	 * @param keyId Name of the key that you want to show up in the users authentication application. Should already be URL
	 * encoded.
	 * @param secret Secret string that will be used when generating the current number.
	 * @param numDigits The number of digits" of the OTP.
	 */
	protected static String generateOtpAuthUrl(String keyId, String secret, int numDigits) {
		StringBuilder sb = new StringBuilder(128);
		addOtpAuthPart(keyId, secret, sb, numDigits);
		return sb.toString();
	}

	/**
	 * Return the QR image url thanks to Google. This can be shown to the user and scanned by the authenticator program as
	 * an easy way to enter the secret.
	 *
	 * @param keyId Name of the key that you want to show up in the users authentication application. Should already be URL
	 * encoded.
	 * @param secret Secret string that will be used when generating the current number.
	 * @param numDigits The number of digits of the OTP. Can be set to {@link #DEFAULT_OTP_LENGTH}.
	 * @param imageDimension The dimension of the image, width and height. Can be set to {@link #DEFAULT_QR_DIMENSION}.
	 */
	protected static String qrImageUrl(String keyId, String secret, int numDigits, int imageDimension) {
		StringBuilder sb = new StringBuilder(128);
		sb.append("https://");
		sb.append(SERVER_URI);
		sb.append("/chart?chs=");
		sb.append(imageDimension + "x" + imageDimension + "&cht=qr&chl=");
//		sb.append(imageDimension + "x" + imageDimension + "&cht=qr&chl=" + imageDimension + "x" + imageDimension + "&chld=M|0&cht=qr&chl=");
		addOtpAuthPart(keyId, secret, sb, numDigits);
		return sb.toString();
	}

	/**
	 * Similar to {@link #validateCurrentNumber(String, int, long)} except exposes other parameters. Mostly for testing.
	 */
	protected static boolean validateCurrentNumber(String base32Secret, int authNumber, long windowMillis, long timeMillis, int timeStepSeconds) {
		return validateCurrentNumber(base32Secret, authNumber, windowMillis, timeMillis, timeStepSeconds, DEFAULT_OTP_LENGTH);
	}

	/**
	 * Similar to {@link #validateCurrentNumber(String, int, long)} except exposes other parameters. Mostly for testing.
	 */
	protected static boolean validateCurrentNumber(String base32Secret, int authNumber, long windowMillis, long timeMillis, int timeStepSeconds, int numDigits) {
		byte[] key = BASE32.decode(base32Secret);
		return validateCurrentNumber(key, authNumber, windowMillis, timeMillis, timeStepSeconds, numDigits);
	}

	/**
	 * Return the string prepended with 0s. Tested as 10x faster than String.format("%06d", ...); Exposed for testing.
	 */
	protected static String zeroPrepend(int num, int digits) {
		String numStr = Integer.toString(num);
		if (numStr.length() >= digits) {
			return numStr;
		}
		StringBuilder sb = new StringBuilder(digits);
		int zeroCount = digits - numStr.length();
		sb.append(BLOCK_OF_ZEROS, 0, zeroCount);
		sb.append(numStr);
		return sb.toString();
	}

	private static void addOtpAuthPart(String keyId, String secret, StringBuilder sb, int numDigits) {
		sb.append("otpauth://totp/").append(keyId).append("%3Fsecret%3D").append(secret).append("%26digits%3D").append(numDigits);
	}

	private static long generateValue(long timeMillis, int timeStepSeconds) {
		return timeMillis / 1000 / timeStepSeconds;
	}

	private static boolean validateCurrentNumber(byte[] key, int authNumber, long windowMillis, long timeMillis, int timeStepSeconds, int numDigits) {
		if (windowMillis <= 0) {
			// just test the current time
			long value = generateValue(timeMillis, timeStepSeconds);
			long generatedNumber = generateNumberFromKeyValue(key, value, numDigits);
			return (generatedNumber == authNumber);
		}
		// maybe check multiple values
		long startValue = generateValue(timeMillis - windowMillis, timeStepSeconds);
		long endValue = generateValue(timeMillis + windowMillis, timeStepSeconds);
		for (long value = startValue; value <= endValue; value++) {
			long generatedNumber = generateNumberFromKeyValue(key, value, numDigits);
			if (generatedNumber == authNumber) {
				return true;
			}
		}
		return false;
	}

}
