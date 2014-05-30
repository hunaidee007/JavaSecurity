package digitalSignature;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.apache.commons.codec.binary.Base64;

public class DigitalSignature {
	
	KeyStore trustStore;
	KeyStore keyStore;
	
	String trustStorePassword;
	String keyStorePass;
	
	
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, SignatureException {
		
		DigitalSignature digitalSignature = new DigitalSignature();
		digitalSignature.loadKeyStore();
		digitalSignature.loadTrustStore();
		
		String data = "ABC";

		// Generate the signature of data key
		byte[] signedEncryptedKey = null;
		Signature dsa = Signature.getInstance("MD5withRSA");
		PrivateKey priv = (PrivateKey) digitalSignature.keyStore.getKey("mykey",
				"password".toCharArray());
		dsa.initSign(priv);
		dsa.update(data.getBytes());
		signedEncryptedKey = dsa.sign();
		String signatureOfKey = Base64.encodeBase64String(signedEncryptedKey);
		System.out.println("Signed Ecrypted Key : " + signatureOfKey);

		/**
		 * At the receiver
		 */

		// Verify signature
		Signature sig = Signature.getInstance("MD5withRSA");
		java.security.cert.Certificate cert =  digitalSignature.trustStore.getCertificate("mykey");
		PublicKey publicKey = cert.getPublicKey();
		
		sig.initVerify(publicKey);
		sig.update(data.getBytes());
		boolean verifies = sig.verify(signedEncryptedKey);
		System.out.println("signature verified:"+verifies);
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
}
