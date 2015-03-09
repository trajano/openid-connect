package net.trajano.openidconnect.crypto.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Random;

import javax.crypto.Cipher;

import org.junit.Assert;
import org.junit.Test;

public class CryptoTest {

    @Test
    public void testRsaCipher() throws Exception {

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        final KeyPair kp = kpg.generateKeyPair();

        byte[] plaintext = new byte[244];
        new Random().nextBytes(plaintext);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] cipherText = cipher.doFinal(plaintext);

        Cipher decipher = Cipher.getInstance("RSA");
        decipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decryptedText = decipher.doFinal(cipherText);

        Assert.assertArrayEquals(plaintext, decryptedText);
    }

    @Test
    public void testEcSignature() throws Exception {

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        final KeyPair kp = kpg.generateKeyPair();

        byte[] plaintext = new byte[5252];
        new Random().nextBytes(plaintext);

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(kp.getPrivate());
        signer.update(plaintext);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(kp.getPublic());
        verifier.update(plaintext);
        Assert.assertTrue(verifier.verify(signature));
    }
}
