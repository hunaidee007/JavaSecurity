package Symmetric.key.without.keytool;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class SymmetricKey {

 public static void main(String[] args) throws Exception {

  //Generate Symmetric key
/*  KeyGenerator generator = KeyGenerator.getInstance("AES");
  generator.init(128);
  SecretKey key = generator.generateKey();*/
 // byte[] symmetricKey =key.getEncoded();
  byte[] symmetricKey = createSHA256("password");
  
  System.out.println("key : "+symmetricKey);
  
  //Encrypt Data
  String encryptedData = encryptWithAESKey("asd", symmetricKey);
  
  System.out.println("Encrypted Data : " + encryptedData);
  
  //Decrypt Data
  System.out.println("Decrypted Data : " +decryptWithAESKey(encryptedData, symmetricKey));

 }



 public static String encryptWithAESKey(String data, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException,
   InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
  SecretKey secKey = new SecretKeySpec(key,"AES");

  Cipher cipher = Cipher.getInstance("AES");
  
  cipher.init(Cipher.ENCRYPT_MODE, secKey);
  byte[] newData = cipher.doFinal(data.getBytes());
  
  return Base64.encodeBase64String(newData);
 }

 public static String decryptWithAESKey(String inputData, byte[] key) throws NoSuchAlgorithmException,
   NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
  Cipher cipher = Cipher.getInstance("AES");
  SecretKey secKey = new SecretKeySpec(key, "AES");

  cipher.init(Cipher.DECRYPT_MODE, secKey);
  byte[] newData = cipher.doFinal(Base64.decodeBase64(inputData));
  return new String(newData);

 }
 private static byte[] createSHA256(String key)
			throws NoSuchAlgorithmException {
		//SHA-256
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(key.getBytes());
		byte byteData[] = md.digest();
		return byteData;
	}
}