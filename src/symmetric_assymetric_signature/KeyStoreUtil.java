package symmetric_assymetric_signature;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class KeyStoreUtil {

	private static KeyStore wcTrustStore;
	private static KeyStore visaKeyStore;

	private static String visaKeyStorePass;
	private static String wcTrustStorePassword;
	private static Cipher dCipher;
	private static Cipher eCipher;

	public KeyStoreUtil() throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException {

		loadTrustStore();
		loadKeyStore();
	}

	private void loadTrustStore() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		wcTrustStore = KeyStore.getInstance("JCEKS");
		wcTrustStorePassword = "password";
		// String filePath = wcCryptoConfig.getTrustStoreFileLocation() +
		// File.separator + wcCryptoConfig.getTrustStoreFile();
		FileInputStream stream = new FileInputStream("pptruststore.jck");
		wcTrustStore.load(stream, wcTrustStorePassword.toCharArray());
	}

	private void loadKeyStore() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		visaKeyStore = KeyStore.getInstance("JCEKS");
		visaKeyStorePass = "password";
		// String filePath = wcCryptoConfig.getKeyStoreFileLocation() +
		// File.separator + wcCryptoConfig.getKeyStoreFile();
		FileInputStream stream = new FileInputStream("ppkeystore.jck");
		visaKeyStore.load(stream, visaKeyStorePass.toCharArray());

	}

	public String decrypt(String encryptedString, String keyAlias)
			throws KeyStoreException, UnrecoverableKeyException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		Key key = visaKeyStore.getKey(keyAlias, visaKeyStorePass.toCharArray());
		dCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		dCipher.init(Cipher.DECRYPT_MODE, key);
		return new String(dCipher.doFinal(Base64.decodeBase64(encryptedString
				.getBytes())));
	}

	public String encrypt(byte[] inputString, String keyAlias)
			throws KeyStoreException, UnrecoverableKeyException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		Key key = null;
		// Key key = scsTrustStore.getKey(keyAlias, scsKeyStorePass);
		if (wcTrustStore.isCertificateEntry(keyAlias)) {
			Certificate cert = wcTrustStore.getCertificate(keyAlias);
			key = cert.getPublicKey();
		} else {
			key = wcTrustStore.getKey(keyAlias, wcTrustStorePassword
					.toCharArray());
		}

		eCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		eCipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(eCipher.doFinal(inputString));
	}

	public byte[] generateSessionKey() throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(128);
		SecretKey key = generator.generateKey();
		System.out.println("key size (in bytes):" + key.getEncoded().length);
		return (key.getEncoded());
	}

	public String encryptWithAESKey(String data, byte[] key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		SecretKey secKey = new SecretKeySpec(key, 0, 16, "AES");
		System.out.println("Secret key size (in bytes):"
				+ secKey.getEncoded().length);
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secKey);
		byte[] newData = cipher.doFinal(data.getBytes());
		return Base64.encodeBase64String(newData);
	}

	public String decryptWithAESKey(String inputData, String key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES");
		SecretKey secKey = new SecretKeySpec(Base64
				.decodeBase64(key.getBytes()), "AES");

		cipher.init(Cipher.DECRYPT_MODE, secKey);
		byte[] newData = cipher.doFinal(Base64.decodeBase64(inputData
				.getBytes()));
		return new String(newData);

	}

	/**
	 * 
	 * @param encryptedKey
	 * @param keyAlias
	 * @return
	 * @throws KeyStoreException
	 * @throws UnrecoverableKeyException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String decryptKey(String encryptedKey, String keyAlias)
			throws KeyStoreException, UnrecoverableKeyException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		Key key = visaKeyStore.getKey(keyAlias, visaKeyStorePass.toCharArray());
		dCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		dCipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedKey = dCipher.doFinal(Base64.decodeBase64(encryptedKey
				.getBytes()));
		SecretKey secKey = new SecretKeySpec(decryptedKey, "AES");
		return new String(Base64.encodeBase64String(secKey.getEncoded()));

	}

	/**
	 * 
	 * @param key
	 * @param keyAlias
	 * @return
	 * @throws KeyStoreException
	 * @throws UnrecoverableKeyException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String encryptKey(byte[] key, String keyAlias)
			throws KeyStoreException, UnrecoverableKeyException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {

		return encrypt(key, keyAlias);

	}

	public byte[] signData(byte[] key) throws NoSuchAlgorithmException,
			NoSuchProviderException, UnrecoverableKeyException,
			KeyStoreException, InvalidKeyException, SignatureException {
		Signature dsa = Signature.getInstance("MD5withRSA");
		PrivateKey priv = (PrivateKey) visaKeyStore.getKey("mykey", "password"
				.toCharArray());
		dsa.initSign(priv);
		dsa.update(key);
		byte[] realSig = dsa.sign();
		return realSig;
	}

	public void verifySignature(byte[] key, byte[] sigToVerify ) throws NoSuchAlgorithmException,
			KeyStoreException, InvalidKeyException, SignatureException {
		Signature sig = Signature.getInstance("MD5withRSA");

		java.security.cert.Certificate cert =  wcTrustStore.getCertificate("mykey");
		PublicKey publicKey = cert.getPublicKey();
		
		sig.initVerify(publicKey);
		sig.update(key);
		boolean verifies = sig.verify(sigToVerify);
		System.out.println("signature verified:"+verifies);
	}

}
