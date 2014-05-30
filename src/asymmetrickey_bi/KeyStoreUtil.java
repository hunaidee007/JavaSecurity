package asymmetrickey_bi;

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

public class KeyStoreUtil {

	private static KeyStore clientTrustStore;
	private static KeyStore clientKeyStore;

	private static KeyStore serverTrustStore;
	private static KeyStore serverKeyStore;

	private static String clientKeyStorePass;
	private static String clientStorePassword;

	private static String serverKeyStorePass;
	private static String serverStorePassword;

	private static Cipher dCipher;
	private static Cipher eCipher;

	public KeyStoreUtil() throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException {

		loadClientTrustStore();
		loadClientKeyStore();
		loadServerTrustStore();
		loadServerKeyStore();
		
	}

	private void loadClientTrustStore() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		clientTrustStore = KeyStore.getInstance("JCEKS");
		clientStorePassword = "password";
		// String filePath = wcCryptoConfig.getTrustStoreFileLocation() +
		// File.separator + wcCryptoConfig.getTrustStoreFile();
		FileInputStream stream = new FileInputStream("bi/clienttruststore.jck");
		clientTrustStore.load(stream, clientStorePassword.toCharArray());
	}

	private void loadClientKeyStore() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		clientKeyStore = KeyStore.getInstance("JCEKS");
		clientKeyStorePass = "password";
		// String filePath = wcCryptoConfig.getKeyStoreFileLocation() +
		// File.separator + wcCryptoConfig.getKeyStoreFile();
		FileInputStream stream = new FileInputStream("bi/clientkeystore.jck");
		clientKeyStore.load(stream, clientKeyStorePass.toCharArray());

	}

	private void loadServerTrustStore() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		serverTrustStore = KeyStore.getInstance("JCEKS");
		serverStorePassword = "password";
		// String filePath = wcCryptoConfig.getTrustStoreFileLocation() +
		// File.separator + wcCryptoConfig.getTrustStoreFile();
		FileInputStream stream = new FileInputStream("bi/servertruststore.jck");
		serverTrustStore.load(stream, serverStorePassword.toCharArray());
	}

	private void loadServerKeyStore() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		serverKeyStore = KeyStore.getInstance("JCEKS");
		serverKeyStorePass = "password";
		// String filePath = wcCryptoConfig.getKeyStoreFileLocation() +
		// File.separator + wcCryptoConfig.getKeyStoreFile();
		FileInputStream stream = new FileInputStream("bi/serverkeystore.jck");
		serverKeyStore.load(stream, serverKeyStorePass.toCharArray());

	}

	public String decryptserver(String encryptedString, String keyAlias)
			throws KeyStoreException, UnrecoverableKeyException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		Key key = serverKeyStore.getKey(keyAlias,
				serverKeyStorePass.toCharArray());
		dCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		dCipher.init(Cipher.DECRYPT_MODE, key);
		return new String(dCipher.doFinal(Base64.decodeBase64(encryptedString
				.getBytes())));
	}

	public String encryptclient(byte[] inputString, String keyAlias)
			throws KeyStoreException, UnrecoverableKeyException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		Key key = null;
		// Key key = scsTrustStore.getKey(keyAlias, scsKeyStorePass);
		if (clientTrustStore.isCertificateEntry(keyAlias)) {
			Certificate cert = clientTrustStore.getCertificate(keyAlias);
			key = cert.getPublicKey();
		} else {
			key = clientTrustStore.getKey(keyAlias,
					clientStorePassword.toCharArray());
		}

		eCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		eCipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(eCipher.doFinal(inputString));
	}
	
	
	public String decryptclientr(String encryptedString, String keyAlias)
			throws KeyStoreException, UnrecoverableKeyException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		Key key = clientKeyStore.getKey(keyAlias,
				clientKeyStorePass.toCharArray());
		dCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		dCipher.init(Cipher.DECRYPT_MODE, key);
		return new String(dCipher.doFinal(Base64.decodeBase64(encryptedString
				.getBytes())));
	}

	public String encryptserver(byte[] inputString, String keyAlias)
			throws KeyStoreException, UnrecoverableKeyException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		Key key = null;
		// Key key = scsTrustStore.getKey(keyAlias, scsKeyStorePass);
		if (serverTrustStore.isCertificateEntry(keyAlias)) {
			Certificate cert = serverTrustStore.getCertificate(keyAlias);
			key = cert.getPublicKey();
		} else {
			key = serverTrustStore.getKey(keyAlias,
					serverStorePassword.toCharArray());
		}

		eCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		eCipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(eCipher.doFinal(inputString));
	}
	



	

}
