package asymmetrickey_uni;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

public class AssymetricKey_UniDirectional {
	KeyStore trustStore;
	KeyStore keyStore;
	String trustStorePassword;
	String keyStorePass;
	Cipher dCipher;
	Cipher eCipher;

	public static void main(String[] args) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableKeyException, InvalidKeyException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {

		AssymetricKey_UniDirectional assymetricKey = new AssymetricKey_UniDirectional();

		// Load TrustStore
		assymetricKey.loadTrustStore();

		// Load Key Store
		assymetricKey.loadKeyStore();

		// Encrypt Data
		String data = "ABCD";
		String encryptedString = assymetricKey
				.encrypt(data.getBytes(), "mykey");
		System.out.println("Encrypted Data : " + encryptedString);

		System.out.println("Decrypted Data : "
				+ assymetricKey.decrypt(encryptedString, "mykey"));

	}

	public void loadTrustStore() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		trustStore = KeyStore.getInstance("JCEKS");
		trustStorePassword = "password";
		FileInputStream stream = new FileInputStream("pptruststore.jck");
		trustStore.load(stream, trustStorePassword.toCharArray());
	}

	public void loadKeyStore() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		keyStore = KeyStore.getInstance("JCEKS");
		keyStorePass = "password";
		FileInputStream stream = new FileInputStream("ppkeystore.jck");
		keyStore.load(stream, keyStorePass.toCharArray());

	}

	public String encrypt(byte[] inputString, String keyAlias)
			throws KeyStoreException, UnrecoverableKeyException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		Key key = null;

		Certificate cert = trustStore.getCertificate(keyAlias);
		key = cert.getPublicKey();

		eCipher = Cipher.getInstance("RSA");
		eCipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(eCipher.doFinal(inputString));
	}

	public String decrypt(String encryptedData, String keyAlias)
			throws KeyStoreException, UnrecoverableKeyException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		Key key = keyStore.getKey(keyAlias, keyStorePass.toCharArray());
		dCipher = Cipher.getInstance("RSA");
		dCipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedData = dCipher.doFinal(Base64
				.decodeBase64(encryptedData));
		return new String(decryptedData);

	}
}
