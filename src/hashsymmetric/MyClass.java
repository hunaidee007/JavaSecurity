package hashsymmetric;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class MyClass {
	public static void main(String[] args) throws Exception {

		String password="password1";
		String data="ABC";
		// Hash User Password using MD5
		byte[] hashedUserPassword = createMD5(password);
		
		System.out.println("Hashed Password : "+Base64.encodeBase64String(hashedUserPassword));
		
		//Encrypt Data using symmetric key created from hash of password
		
		String encryptedData=encryptData(data,hashedUserPassword);
		System.out.println("Encrypted Data : "+ encryptedData);
		
		//Encrypt Data using symmetric key created from hash of password
		String decryptedData=decryptData(encryptedData,hashedUserPassword);
		System.out.println("Decrypted Data : "+decryptedData);
		
		
		
	}

	private static String decryptData(String encryptedData, byte[] hashedUserPassword) throws Exception {
		//Generate Key using hash of password
		SecretKey secKey = new SecretKeySpec(hashedUserPassword, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, secKey);
		
		byte[] decryptedData=cipher.doFinal(Base64.decodeBase64(encryptedData));
		return new String(decryptedData);
		
	}

	
	private  static String encryptData(String data, byte[] hashedUserPassword) throws Exception{
		//Generate Key using hash of password
		SecretKey secKey = new SecretKeySpec(hashedUserPassword, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secKey);
		
		byte[] newData = cipher.doFinal(data.getBytes());
		
		String encryptedData = Base64.encodeBase64String(newData);
		
		return encryptedData;
	}
	
	private static byte[] createMD5(String key)
			throws NoSuchAlgorithmException {
		//SHA-256
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(key.getBytes());
		byte byteData[] = md.digest();
		return byteData;
	}
	
}
