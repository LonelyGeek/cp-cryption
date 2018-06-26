package com.carrypast.crypt.digest.hmac;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Chen.Wang
 */
public class HMACMain {

    private static final String SOURCE_STR = "iBigData security hmac";

    public static void main(String[] args) {
        jdkHmacMD5();
        bcHmacMD5();
        bcHmacSHA1();
    }

    public static void jdkHmacMD5() {
        try {
            //初始化
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD5");
            //产生密钥
            SecretKey secretKey = keyGenerator.generateKey();
            //获得密钥
            byte[] key = secretKey.getEncoded();

            //还原密钥
            SecretKey restoreSecretKey = new SecretKeySpec(key, "HmacMD5");

            //实例化mac
            Mac mac = Mac.getInstance(restoreSecretKey.getAlgorithm());

            //初始化mac
            mac.init(restoreSecretKey);
            byte[] hmacMD5Bytes = mac.doFinal(SOURCE_STR.getBytes());
            System.out.println("jdk hmacMD5" + Hex.encodeHexString(hmacMD5Bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bcHmacMD5() {
        HMac hMac = new HMac(new MD5Digest());
        hMac.init(new KeyParameter(org.bouncycastle.util.encoders.Hex.decode("aaaaaaaaaa")));
        hMac.update(SOURCE_STR.getBytes(),0, SOURCE_STR.getBytes().length);
        // 执行摘要
        byte[] hmacMD5Bytes = new byte[hMac.getMacSize()];
        hMac.doFinal(hmacMD5Bytes, 0);
        System.out.println("bc hmacMD5:" + org.bouncycastle.util.encoders.Hex.toHexString(hmacMD5Bytes));
    }

    public static void bcHmacSHA1() {
        HMac hMac = new HMac(new SHA1Digest());
        hMac.init(new KeyParameter(org.bouncycastle.util.encoders.Hex.decode("aaaaaaaaaa")));
        hMac.update(SOURCE_STR.getBytes(),0, SOURCE_STR.getBytes().length);
        // 执行摘要
        byte[] hmacMD5Bytes = new byte[hMac.getMacSize()];
        hMac.doFinal(hmacMD5Bytes, 0);
        System.out.println("bc hmacSHA1:" + org.bouncycastle.util.encoders.Hex.toHexString(hmacMD5Bytes));
    }
}
