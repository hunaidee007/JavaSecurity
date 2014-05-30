package asymmetrickey_bi;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AsymmetricKey_bi {
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		
		KeyStoreUtil keyStoreUtil = new KeyStoreUtil();

		//Client sends encrypted data to server
		String clientData="ABC";
		String clientDataEncrypted =keyStoreUtil.encryptclient(clientData.getBytes(), "server");
		
		//Server recieves data and decrpyts it
		System.out.println(keyStoreUtil.decryptserver(clientDataEncrypted, "server"));
		
		
		//Server Sends data to client
		String serverData="Hello";
		String serverDataEncrypted =keyStoreUtil.encryptserver(serverData.getBytes(), "client");
		
		//Client recieves data and decrpyts it
		System.out.println(keyStoreUtil.decryptclientr(serverDataEncrypted, "client"));
		
	}
}
