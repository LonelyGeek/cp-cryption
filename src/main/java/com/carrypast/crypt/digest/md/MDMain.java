package com.carrypast.crypt.digest.md;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * @author Chen.Wang
 */
public class MDMain {

    private static final String SOURCE_STR = "iBigData security md";

    public static void main(String[] args) {
        jdkMD5();
        jdkMD2();
        bcMD4();
        jdkBCMD4();
        bcMD5();
        ccMD5();
        ccMD2();
    }

    private static void jdkMD5() {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] md5Bytes = md.digest(SOURCE_STR.getBytes());
            System.out.println("JDK MD5:" + Hex.encodeHexString(md5Bytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static void jdkMD2() {
        try {
            MessageDigest md = MessageDigest.getInstance("MD2");
            byte[] md2Bytes = md.digest(SOURCE_STR.getBytes());
            System.out.println("JDK MD2:" + Hex.encodeHexString(md2Bytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static void bcMD4() {
        try {
            Digest digest = new MD4Digest();
            digest.update(SOURCE_STR.getBytes(), 0, SOURCE_STR.getBytes().length);
            byte[] md4Bytes = new byte[digest.getDigestSize()];
            digest.doFinal(md4Bytes, 0);
            System.out.println("BC MD4:" + org.bouncycastle.util.encoders.Hex.toHexString(md4Bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void jdkBCMD4() {
        try {
            Security.addProvider(new BouncyCastleProvider());
            MessageDigest md = MessageDigest.getInstance("MD4");
            byte[] md4Bytes = md.digest(SOURCE_STR.getBytes());
            System.out.println("JDK BC MD4:" + Hex.encodeHexString(md4Bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bcMD5() {
        try {
            Digest digest = new MD5Digest();
            digest.update(SOURCE_STR.getBytes(), 0, SOURCE_STR.getBytes().length);
            byte[] md4Bytes = new byte[digest.getDigestSize()];
            digest.doFinal(md4Bytes, 0);
            System.out.println("BC MD5:" + org.bouncycastle.util.encoders.Hex.toHexString(md4Bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void ccMD5() {
//        System.out.println("CC MD5:" + Hex.encodeHexString(DigestUtils.getMd5Digest().digest(src.getBytes())));
        System.out.println("CC MD5:" + DigestUtils.md5Hex(SOURCE_STR.getBytes()));
    }

    private static void ccMD2() {
        System.out.println("CC MD2:" + DigestUtils.md2Hex(SOURCE_STR.getBytes()));
    }

}
