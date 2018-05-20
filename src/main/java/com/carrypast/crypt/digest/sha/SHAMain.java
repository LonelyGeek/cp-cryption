package com.carrypast.crypt.digest.sha;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * @author Chen.Wang
 */
public class SHAMain {

    private static String SOURCE_STR = "iBigData security sha";

    private static void main(String[] args) {
        jdkSHA1();
        bcSHA1();
        bcSHA224();
        bcSHA224_2();
        ccSHA1();
    }

    private static void jdkSHA1() {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA");
            sha.update(SOURCE_STR.getBytes());
            System.out.println("jdk sha-1:" + Hex.encodeHexString(sha.digest()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static void bcSHA1() {
        Digest digest = new SHA1Digest();
        digest.update(SOURCE_STR.getBytes(),0, SOURCE_STR.getBytes().length);
        byte[] sha1Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(sha1Bytes, 0);
        System.out.println("bc sha-1:" + org.bouncycastle.util.encoders.Hex.toHexString(sha1Bytes));
    }

    private static void bcSHA224() {
        Digest digest = new SHA224Digest();
        digest.update(SOURCE_STR.getBytes(), 0, SOURCE_STR.getBytes().length);
        byte[] sha224Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(sha224Bytes, 0);
        System.out.println("bc sha-224:" + org.bouncycastle.util.encoders.Hex.toHexString(sha224Bytes));
    }

    private static void bcSHA224_2() {
        Security.addProvider(new BouncyCastleProvider());
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA224");
            byte[] sha224Bytes = digest.digest(SOURCE_STR.getBytes());
            System.out.println("bc sha-224-2 : " + org.bouncycastle.util.encoders.Hex.toHexString(sha224Bytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static void ccSHA1() {
        System.out.println("cc sha1 - 1:" + DigestUtils.sha1Hex(SOURCE_STR.getBytes()));
        System.out.println("cc sha1 - 2:" + DigestUtils.sha1Hex(SOURCE_STR));
    }
}
