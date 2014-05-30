package symmetric_assymetric_signature;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Symmetric_AsymmetricKey {

	public static void main(String[] args) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException,
			UnrecoverableKeyException, NoSuchProviderException,
			SignatureException {

		/**
		 * At the client side
		 */
		KeyStoreUtil keyStoreUtil = new KeyStoreUtil();
		// Generate Symmetric key
		byte[] symmetrickey = keyStoreUtil.generateSessionKey();
		// Encrypt data by symmetric key
		String data = "ABC";
		System.out.println("Data : " + data);
		String encryptedData = keyStoreUtil.encryptWithAESKey(data,
				symmetrickey);
		System.out.println("encryptedData : " + encryptedData);

		// Encrypt symmetric key using trustore
		String encryptedKey = keyStoreUtil.encryptKey(symmetrickey, "mykey");
		System.out.println("encryptedKey : " + encryptedKey);



		// Decrypt symmteric key using keystore
		String decryptedKey = keyStoreUtil.decryptKey(encryptedKey, "mykey");
		System.out.println("decryptedKey : " + decryptedKey);

		// Decrypt data using decrypted symetric key

		System.out.println("Decrypted Data : "
				+ keyStoreUtil.decryptWithAESKey(encryptedData, decryptedKey));

	}
}
