package com.carrypast.crypt.base64;

import org.apache.commons.codec.binary.Base64;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;

/**
 * @author Chen.Wang
 */
public class Base64Main {

    private static final String SOURCE_STR = "iBigData security base64";

    public static void main(String[] args) throws Exception {
        jdkBase64();
        commonsCodesBase64();
        bouncyCastleBase64();
    }

    public static void jdkBase64() throws IOException {
        BASE64Encoder encoder = new BASE64Encoder();
        String encode = encoder.encode(SOURCE_STR.getBytes());


        System.out.println("encode:" + encode);

        BASE64Decoder decoder = new BASE64Decoder();
        System.out.println("decode" + new String (decoder.decodeBuffer(encode)));
    }

    public static void commonsCodesBase64() {

        byte[] encodeBytes = Base64.encodeBase64(SOURCE_STR.getBytes());
        System.out.println("encode:" + new String(encodeBytes));

        System.out.println("encode2:" + Base64.encodeBase64String(SOURCE_STR.getBytes()));


        byte[] decodeBytes = Base64.decodeBase64(encodeBytes);
        System.out.println("decode" + new String(decodeBytes));
    }

    public static void bouncyCastleBase64() {

        byte[] encodeBytes = org.bouncycastle.util.encoders.Base64.encode(SOURCE_STR.getBytes());
        System.out.println("encode:" + new String(encodeBytes));

        byte[] decodeBytes = org.bouncycastle.util.encoders.Base64.decode(encodeBytes);
        System.out.println("decode" + new String(decodeBytes));
    }
}
