package com.carrypast.crypt.asymmetric.eigamal;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author Chen.Wang
 */
public class ELGamalMain {

    /**
     * 需要将%JAVA_HOME%/jre/lib/security/policy/unlimited 目录下两个jar包
     *
     * 复制到 %JAVA_HOME%/jre/lib/security
     */

    public static final String SOURCE_STR = "iBigData security eigamal";

    private static final String KEY_ALGORITHM = "ElGamal";

    public static void main(String[] args) {
        bcELGamal();
    }

    public static void bcELGamal() {
        try {

            //只提供公钥加密、私钥解密
            Security.addProvider(new BouncyCastleProvider());
            //1.初始化密钥
            AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance(KEY_ALGORITHM);
            algorithmParameterGenerator.init(256);
            AlgorithmParameters algorithmParameter = algorithmParameterGenerator.generateParameters();
            DHParameterSpec dhParameterSpec = algorithmParameter.getParameterSpec(DHParameterSpec.class);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(dhParameterSpec, new SecureRandom());

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey eLGamalPublicKey = keyPair.getPublic();
            PrivateKey eLGamalPrivateKey = keyPair.getPrivate();

            System.out.println("Public Key:" + Base64.encodeBase64String(eLGamalPublicKey.getEncoded()));
            System.out.println("Private Key:" + Base64.encodeBase64String(eLGamalPrivateKey.getEncoded()));


            //2、加密
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(eLGamalPublicKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] result = cipher.doFinal(SOURCE_STR.getBytes());
            System.out.println("加密：" + Base64.encodeBase64String(result));

            //3、解密
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(eLGamalPrivateKey.getEncoded());
            keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            cipher = Cipher.getInstance(KEY_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            result = cipher.doFinal(result);
            System.out.println("解密：" + Base64.encodeBase64String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
