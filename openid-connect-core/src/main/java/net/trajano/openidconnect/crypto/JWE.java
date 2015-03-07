package net.trajano.openidconnect.crypto;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.trajano.openidconnect.auth.JoseHeader;
import net.trajano.openidconnect.auth.JsonWebToken;
import net.trajano.openidconnect.internal.CharSets;

public class JWE {

    public static byte[] decrypt(final String jwe,
            final JsonWebKey jwk) throws IOException,
            GeneralSecurityException {

        final JsonWebToken jsonWebToken = new JsonWebToken(jwe);
        if (jsonWebToken.getNumberOfPayloads() != 4) {
            throw new GeneralSecurityException("invalid number of payloads in JWT for JWE");
        }
        final byte[] encryptedKey = jsonWebToken.getPayload(0);
        final byte[] initializationVector = jsonWebToken.getPayload(1);
        final byte[] cipherText = jsonWebToken.getPayload(2);
        final byte[] authenticationTag = jsonWebToken.getPayload(3);
        final PrivateKey privateKey = (PrivateKey) jwk.toJcaKey();

        final JoseHeader joseHeader = jsonWebToken.getJoseHeader();
        final Cipher encryptionKeyCipher = Cipher.getInstance(joseHeader.getAlg()
                .toJca());
        encryptionKeyCipher.init(Cipher.DECRYPT_MODE, privateKey);
        final byte[] decryptedKey = encryptionKeyCipher.doFinal(encryptedKey);

        final SecretKey contentEncryptionKey = new SecretKeySpec(decryptedKey, "AES");

        final byte[] aad = jsonWebToken.getJoseHeaderEncoded()
                .getBytes(CharSets.US_ASCII);

        final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(authenticationTag.length * 8, initializationVector);

        final Cipher contentCipher = Cipher.getInstance(joseHeader.getEnc()
                .toJca());
        contentCipher.init(Cipher.DECRYPT_MODE, contentEncryptionKey, gcmParameterSpec);
        contentCipher.updateAAD(aad);

        contentCipher.update(cipherText);
        final byte[] plaintext = contentCipher.doFinal(authenticationTag);
        return plaintext;
    }

    public static String encrypt(byte[] plaintext,
            JsonWebKey jwk,
            JsonWebAlgorithm alg,
            JsonWebAlgorithm enc) throws IOException,
            GeneralSecurityException {

        JoseHeader joseHeader = new JoseHeader();
        joseHeader.setAlg(alg);
        joseHeader.setEnc(enc);
        String encodedJoseHeader = Base64Url.encode(joseHeader.toString());
        StringBuilder b = new StringBuilder(encodedJoseHeader);
        b.append('.');

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.getBits());
        SecretKey secretKey = keyGenerator.generateKey();

        final byte[] cek = secretKey.getEncoded();

        final Cipher cekCipher = Cipher.getInstance(alg.toJca());
        cekCipher.init(Cipher.ENCRYPT_MODE, jwk.toJcaKey());
        final byte[] encryptedCek = cekCipher.doFinal(cek);

        b.append(Base64Url.encode(encryptedCek));
        b.append('.');

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[96];
        random.nextBytes(iv);

        b.append(Base64Url.encode(iv));
        b.append('.');

        final GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        final Cipher contentCipher = Cipher.getInstance("AES/GCM/NoPadding");
        contentCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), spec);
        contentCipher.updateAAD(encodedJoseHeader.getBytes(CharSets.US_ASCII));

        final byte[] cipherTextAndAuthenticationTag = contentCipher.doFinal(plaintext);
        final String cipherText = Base64Url.encode(cipherTextAndAuthenticationTag, 0, cipherTextAndAuthenticationTag.length - 128 / 8);
        final String authenticationTag = Base64Url.encode(cipherTextAndAuthenticationTag, cipherTextAndAuthenticationTag.length - 128 / 8, 128 / 8);

        b.append(cipherText);
        b.append('.');
        b.append(authenticationTag);

        return b.toString();
    }
}
