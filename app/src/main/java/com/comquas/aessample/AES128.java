package com.comquas.aessample;

import android.util.Base64;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by htainlinshwe on 31/1/15.
 */
public class AES128 {

	public static String encrypt_text(String input,String key_text) throws Exception {


		//because AES key must be 16 characters. So, it may not. This will generate to correct key
		byte[] keyStart = key_text.getBytes();
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(keyStart);
		kgen.init(128, sr); // 192 and 256 bits may not be available
		SecretKey skey = kgen.generateKey();

		//SecretKeySpec skey = new SecretKeySpec(key_text.getBytes(), "AES");

		byte[] key = skey.getEncoded();


		byte[] encryptedData = encrypt(key,input.getBytes());


		return Base64.encodeToString(encryptedData,0);

	}

	public static String decrypt_text(String base64_text,String key_text) throws Exception {


		//because AES key must be 16 characters. So, it may not. This will generate to correct key
		byte[] keyStart = key_text.getBytes();
//        KeyGenerator kgen = KeyGenerator.getInstance("AES");
//        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
//        sr.setSeed(keyStart);
//        kgen.init(128, sr); // 192 and 256 bits may not be available
//        SecretKey skey = kgen.generateKey();

//        SecretKeySpec skey = new SecretKeySpec(key_text.getBytes(), "AES");
		byte[] key =keyStart;


		byte[] encryptedData = Base64.decode(base64_text,0);

		byte[] original = decrypt(key,encryptedData);

		String s = new String(original,"UTF-8");

		return s;

	}
	private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");

		byte[] iv = "0123456789123456".getBytes();

		cipher.init(Cipher.ENCRYPT_MODE, skeySpec,new IvParameterSpec(iv));

		byte[] encrypted = cipher.doFinal(clear);
		return encrypted;

	}

	private static byte[] decrypt(byte[] raw, byte[] encrypted) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");


		//        KeyGenerator kgen = KeyGenerator.getInstance("AES");
//        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
//        sr.setSeed(keyStart);
//        kgen.init(128, sr); // 192 and 256 bits may not be available
//        SecretKey skey = kgen.generateKey();

//        SecretKeySpec skey = new SecretKeySpec(key_text.getBytes(), "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		byte[] iv = "0123456789123456".getBytes();

		cipher.init(Cipher.DECRYPT_MODE, skeySpec,new IvParmeterSpec(iv));

		byte[] decrypted = cipher.doFinal(encrypted);
		return decrypted;
	}

}