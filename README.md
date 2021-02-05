Two (2) Factor Authentication (2FA) Java Code
=============================================

2 Factor Authentication (2FA) Java code which used the Time-based One-time Password (TOTP) algorithm.
You can use this code with the Google Authenticator mobile app or the Authy mobile or browser app.

* See the [wikipedia page about TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm).	
* Maven packages are published via [[Maven Central](https://mvnrepository.com/artifact/com.github.embuc)]

## To get this to work you:

1. Use `generateBase32Secret()` to generate a (20-byte (160-bit) as default length) secret key in base-32 format for the user.  For example: `"RIGUTCUXDANCPJ7IFRBB"`
2. Store the secret key in the database associated with the user account.
3. Display the QR image URL returned by `qrImageUrl(...)` to the user.  Here's a sample which uses GoogleAPIs:  
![Sample QR Image](https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=200x200&chld=M|0&cht=qr&chl=otpauth://totp/user@nano2fa.com%3Fsecret%3DRIGUTCUXDANCPJ7IFRBB%26digits%3D6)
4. User uses the image to load the secret key into his authenticator application.

## Whenever the user logs in:

1. The user enters the number from the authenticator application into the login form on the web server.
2. The web server reads the secret associated with the user account from the database.
3. The server compares the user input with the output from `generateCurrentNumberString(...)`.
4. If they are equal then the user is allowed to log in.

For more details, see the [example program](https://github.com/embuc/nano-2FA/blob/master/src/test/java/se/embuc/nano2fa/TwoFactorAuthUsageExample.java).

# Maven Configuration

``` xml
<dependencies>
	<dependency>
		<groupId>com.github.embuc</groupId>
		<artifactId>nano2fa</artifactId>
		<version>1.5</version>
	</dependency>
</dependencies>
```

# ChangeLog Release Notes

See the [ChangeLog.txt file](changelog.txt).
