package se.embuc.nano2fa;

/**
 * Little test program to show how to use the {@link TimeBasedOneTimePasswordUtil} utility class.
 *
 * @author graywatson
 * @author Emir Bucalovic
 */
public class TwoFactorAuthUsageExample {

	/**
	 * The main method - run to see codes generate (compare with 3rd party such as Google Authenticator).
	 *
	 * @param args the arguments
	 * @throws Exception the exception
	 */
	public static void main(String[] args) throws Exception {

		/* String base32Secret = TimeBasedOneTimePasswordUtil.generateBase32Secret(); */
		String base32Secret = "RIGUTCUXDANCPJ7IFRBB";

		System.out.println("secret = " + base32Secret);

		/* This is the name of the key which can be displayed by the authenticator program */
		String keyId = "user@nano2fa.com";
		/* Generate the QR code */
		System.out.println("Image url = " + TimeBasedOneTimePasswordUtil.qrImageUrl(keyId, base32Secret));
		/* We can display this image to the user to let them load it into their auth program */

		/* We can use the code here and compare it against user input. */
		String code = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(base32Secret);
		TimeBasedOneTimePasswordUtil.validateCurrentNumber(base32Secret, 0);

		/* Visualize how the number changes over time. */
		while (true) {
			long diff = TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS - ((System.currentTimeMillis() / 1000) % TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS);
			code = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(base32Secret);
			System.out.println("Secret code = " + code + ", change in " + diff + " seconds");
			Thread.sleep(1000);
		}
	}
}
