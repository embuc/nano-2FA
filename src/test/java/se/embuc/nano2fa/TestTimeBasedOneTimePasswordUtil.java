package se.embuc.nano2fa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TestTimeBasedOneTimePasswordUtil.
 *
 * @author graywatson
 * @author Emir Bucalovic
 * @since 06 Dec 2016
 */
public class TestTimeBasedOneTimePasswordUtil {

	@Test
	public void testZeroPrepend() {
		Random random = new Random();
		for (int i = 0; i < 10000; i++) {
			int num = random.nextInt(1000000);
			/**
			 * NOTE: Did a speed test of these and the zeroPrepend is ~13x faster.
			 */
			assertEquals(String.format("%06d", num), TimeBasedOneTimePasswordUtil.zeroPrepend(num, 6));
		}
	}

	@Test
	public void testVariousKnownSecretTimeCodes() {
		String secret = "NY4A5CPJZ46LXZCP";

		testStringAndNumber(secret, 1000L, 748810, "748810");
		testStringAndNumber(secret, 7451000L, 325893, "325893");
		testStringAndNumber(secret, 15451000L, 64088, "064088");
		testStringAndNumber(secret, 348402049542546145L, 9637, "009637");
		testStringAndNumber(secret, 2049455124374752571L, 743, "000743");
		testStringAndNumber(secret, 1359002349304873750L, 92, "000092");
		testStringAndNumber(secret, 6344447817348357059L, 7, "000007");
		testStringAndNumber(secret, 2125701285964551130L, 0, "000000");

		testStringAndNumber(secret, 7451000L, 3, "3", 1);
		testStringAndNumber(secret, 7451000L, 93, "93", 2);
		testStringAndNumber(secret, 7451000L, 893, "893", 3);
		testStringAndNumber(secret, 7451000L, 5893, "5893", 4);
		testStringAndNumber(secret, 7451000L, 25893, "25893", 5);
		testStringAndNumber(secret, 7451000L, 325893, "325893", 6);
		testStringAndNumber(secret, 7451000L, 9325893, "9325893", 7);
		testStringAndNumber(secret, 7451000L, 89325893, "89325893", 8);

		testStringAndNumber(secret, 1000L, 34748810, "34748810", 8);
		testStringAndNumber(secret, 7451000L, 89325893, "89325893", 8);
		testStringAndNumber(secret, 15451000L, 67064088, "67064088", 8);
		testStringAndNumber(secret, 5964551130L, 5993908, "05993908", 8);
		testStringAndNumber(secret, 348402049542546145L, 26009637, "26009637", 8);
		testStringAndNumber(secret, 2049455124374752571L, 94000743, "94000743", 8);
		testStringAndNumber(secret, 1359002349304873750L, 86000092, "86000092", 8);
		testStringAndNumber(secret, 6344447817348357059L, 80000007, "80000007", 8);
		testStringAndNumber(secret, 2125701285964551130L, 24000000, "24000000", 8);
	}

	private void testStringAndNumber(String secret, long timeMillis, long expectedNumber, String expectedString) {
		testStringAndNumber(secret, timeMillis, expectedNumber, expectedString, TimeBasedOneTimePasswordUtil.DEFAULT_OTP_LENGTH);
	}

	private void testStringAndNumber(String secret, long timeMillis, long expectedNumber, String expectedString, int length) {
		String str = TimeBasedOneTimePasswordUtil.generateNumberString(secret, timeMillis, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS, length);
		assertEquals(length, str.length());
		assertEquals(expectedString, str);
		assertEquals(expectedNumber, TimeBasedOneTimePasswordUtil.generateNumber(secret, timeMillis, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS, length));
	}

	@Test
	public void testValidate() {
		String secret = "NY4A5CPJZ46LXZCP";
		assertEquals(162123, TimeBasedOneTimePasswordUtil.generateNumber(secret, 7439999, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 325893, 0, 7455000, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertFalse(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 948323, 0, 7455000, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		// this should of course match
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 325893, 15000, 7455000, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));

		/*
		 * Test upper window which starts +15000 milliseconds.
		 */

		// but this is the next value and the window doesn't quite take us to the next time-step
		assertFalse(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 948323, 14999, 7455000, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		// but this is the next value which is 15000 milliseconds ahead
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 948323, 15000, 7455000, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));

		/*
		 * The lower window is less than -15000 milliseconds so we have to test a window of 15001.
		 */

		// but this is the previous value and the window doesn't quite take us to the previous time-step
		assertFalse(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 287511, 15000, 7455000, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		// but this is the previous value which is 15001 milliseconds earlier
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 162123, 15001, 7455000, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
	}

	@Test
	public void testGenerateSecret() {
		assertEquals(20, TimeBasedOneTimePasswordUtil.generateBase32Secret().length());
		assertEquals(16, TimeBasedOneTimePasswordUtil.generateBase32Secret(16).length());
		assertEquals(1, TimeBasedOneTimePasswordUtil.generateBase32Secret(1).length());
	}

	@Test
	public void testWindow() {
		String secret = TimeBasedOneTimePasswordUtil.generateBase32Secret();
		long window = 10000;
		Random random = new Random();
		for (int i = 0; i < 1000; i++) {
			long now = random.nextLong();
			if (now < 0) {
				now = -now;
			}
			int number = TimeBasedOneTimePasswordUtil.generateNumber(secret, now, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS);
			assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now - window, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
			assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
			assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now + window, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		}
	}

	@Test
	public void testWindowStuff() {
		String secret = TimeBasedOneTimePasswordUtil.generateBase32Secret();
		long window = 10000;
		long now = 5462669356666716002L;
		int number = TimeBasedOneTimePasswordUtil.generateNumber(secret, now, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS);
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now - window, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now + window, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));

		now = 8835485943423840000L;
		number = TimeBasedOneTimePasswordUtil.generateNumber(secret, now, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS);
		assertFalse(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now - window - 1, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now - window, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now + window, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));

		now = 8363681401523009999L;
		number = TimeBasedOneTimePasswordUtil.generateNumber(secret, now, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS);
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now - window, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now + window, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertFalse(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now + window + 1, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
	}

	@Test
	public void testCoverage() {
		String secret = "ny4A5CPJZ46LXZCP";
		TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 948323, 15000);
		assertEquals(TimeBasedOneTimePasswordUtil.DEFAULT_OTP_LENGTH, TimeBasedOneTimePasswordUtil.generateCurrentNumberString(secret).length());

		assertNotNull(TimeBasedOneTimePasswordUtil.generateOtpAuthUrl("key", secret));
		assertNotNull(TimeBasedOneTimePasswordUtil.generateOtpAuthUrl("key", secret, 8));
		assertNotNull(TimeBasedOneTimePasswordUtil.qrImageUrl("key", secret));
		assertNotNull(TimeBasedOneTimePasswordUtil.qrImageUrl("key", secret, 3));
		assertNotNull(TimeBasedOneTimePasswordUtil.qrImageUrl("key", secret, 3, 500));
	}

	@Test
	public void shouldThrowForEmptyKey() {
		byte[] byteKey = new byte[0];
		long value = 123456l;
		int numDigits = 6;
		assertThrows(IllegalArgumentException.class, () -> TimeBasedOneTimePasswordUtil.generateNumberFromKeyValue(byteKey, value, numDigits));
	}

	@Test
	public void shouldThrowForNullKey() {
		byte[] byteKey = null;
		long value = 123456l;
		int numDigits = 6;
		assertThrows(IllegalArgumentException.class, () -> TimeBasedOneTimePasswordUtil.generateNumberFromKeyValue(byteKey, value, numDigits));
	}

	@Test
	public void shouldValidateCorrectlyDefaultAPICallChain() throws Exception {
		String base32Secret = TimeBasedOneTimePasswordUtil.generateBase32Secret();
		String numberString = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(base32Secret);
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(base32Secret, Integer.valueOf(numberString).intValue()));
	}

	@Test
	public void shouldGenerateFormattedRecoveryCode() {
		String recoveryCode = TimeBasedOneTimePasswordUtil.generateFormattedRecoveryCode();
		assertNotNull(recoveryCode);
		assertEquals(24, recoveryCode.length());
	}
}
