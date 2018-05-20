package com.carrypast.crypt.symmetric.aes;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.Security;

/**
 * @author Chen.Wang
 */
public class AESMain {

    public static final String SOURCE_STR = "iBigData security aes";

    public static void main(String[] args) {
        jdkAES();
        bcAES();
    }

    public static void jdkAES() {

        try {
            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//            keyGenerator.init(new SecureRandom());
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] keyBytes = secretKey.getEncoded();

            //key 转换
            Key key = new SecretKeySpec(keyBytes, "AES");

            //加密
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] result = cipher.doFinal(SOURCE_STR.getBytes());
            System.out.println("jdk aes encrypt:" + Base64.encodeBase64String(result));


            //解密
            cipher.init(Cipher.DECRYPT_MODE, key);
            result = cipher.doFinal(result);
            System.out.println("jdk aes decrypt:" + new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bcAES() {
        try {
            Security.addProvider(new BouncyCastleProvider());

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
            keyGenerator.init(128);
            byte[] keyBytes = keyGenerator.generateKey().getEncoded();

            Key key = new SecretKeySpec(keyBytes, "AES");

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] result =  cipher.doFinal(SOURCE_STR.getBytes());
            System.out.println("bc aes encrypt:" + Base64.encodeBase64String(result));

            cipher.init(Cipher.DECRYPT_MODE, key);
            result = cipher.doFinal(result);
            System.out.println("bc aes decrypt:" + new String(result));


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
