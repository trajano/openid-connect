package net.trajano.openidconnect.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.trajano.openidconnect.auth.JoseHeader;
import net.trajano.openidconnect.internal.CharSets;

public class JWE {

    public static byte[] decrypt(final String jwe,
            final JsonWebKey jwk) throws IOException,
            GeneralSecurityException, DataFormatException {

        final JsonWebToken jsonWebToken = new JsonWebToken(jwe);
        if (jsonWebToken.getNumberOfPayloads() != 4) {
            throw new GeneralSecurityException("invalid number of payloads in JWT for JWE");
        }
        final byte[] encryptedKey = jsonWebToken.getPayload(0);
        final byte[] initializationVector = jsonWebToken.getPayload(1);
        final byte[] cipherText = jsonWebToken.getPayload(2);
        final byte[] authenticationTag = jsonWebToken.getPayload(3);
        final PrivateKey privateKey = (PrivateKey) jwk.toJcaKey();

        final Cipher encryptionKeyCipher = Cipher.getInstance(jsonWebToken.getAlg()
                .toJca());
        encryptionKeyCipher.init(Cipher.DECRYPT_MODE, privateKey);
        final byte[] decryptedKey = encryptionKeyCipher.doFinal(encryptedKey);

        final SecretKey contentEncryptionKey = new SecretKeySpec(decryptedKey, "AES");

        final byte[] aad = jsonWebToken.getJoseHeaderEncoded()
                .getBytes(CharSets.US_ASCII);

        final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(authenticationTag.length * 8, initializationVector);

        final Cipher contentCipher = Cipher.getInstance(jsonWebToken.getEnc()
                .toJca());
        contentCipher.init(Cipher.DECRYPT_MODE, contentEncryptionKey, gcmParameterSpec);
        contentCipher.updateAAD(aad);

        contentCipher.update(cipherText);
        byte[] plaintext = contentCipher.doFinal(authenticationTag);
        boolean compress = "DEF".equals(jsonWebToken.getZip());
        if (compress) {
            return inflate(plaintext);
        } else {
            return plaintext;
        }
    }

    public static String encrypt(byte[] plaintext,
            JsonWebKey jwk,
            JsonWebAlgorithm alg,
            JsonWebAlgorithm enc) throws IOException,
            GeneralSecurityException {

        return encrypt(plaintext, jwk, alg, enc, false);
    }

    public static String encrypt(byte[] plaintext,
            JsonWebKey jwk,
            JsonWebAlgorithm alg,
            JsonWebAlgorithm enc,
            boolean compress) throws IOException,
            GeneralSecurityException {

        JoseHeader joseHeader = new JoseHeader();
        joseHeader.setAlg(alg);
        joseHeader.setEnc(enc);
        joseHeader.setZip(compress ? "DEF" : null);
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

        final int authenticationTagBits = 128;
        final GCMParameterSpec spec = new GCMParameterSpec(authenticationTagBits, iv);
        final Cipher contentCipher = Cipher.getInstance("AES/GCM/NoPadding");
        contentCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), spec);
        contentCipher.updateAAD(encodedJoseHeader.getBytes(CharSets.US_ASCII));

        final byte[] cipherTextAndAuthenticationTag;
        if (compress) {
            cipherTextAndAuthenticationTag = contentCipher.doFinal(deflate(plaintext));
        } else {
            cipherTextAndAuthenticationTag = contentCipher.doFinal(plaintext);
        }
        /*
         * final ByteArrayOutputStream baos = new
         * ByteArrayOutputStream(plaintext.length); final OutputStream os; if
         * (compress) { os = new CipherOutputStream(new
         * DeflaterOutputStream(baos), contentCipher); } else { os = new
         * CipherOutputStream(baos, contentCipher); } os.write(plaintext);
         * os.close(); final byte[] cipherTextAndAuthenticationTag =
         * baos.toByteArray();
         */

        final String cipherText = Base64Url.encode(cipherTextAndAuthenticationTag, 0, cipherTextAndAuthenticationTag.length - authenticationTagBits / 8);
        final String authenticationTag = Base64Url.encode(cipherTextAndAuthenticationTag, cipherTextAndAuthenticationTag.length - authenticationTagBits / 8, authenticationTagBits / 8);

        b.append(cipherText);
        b.append('.');
        b.append(authenticationTag);

        return b.toString();
    }

    private static byte[] deflate(byte[] uncompressed) throws IOException {

        Deflater deflater = new Deflater(9);
        deflater.setInput(uncompressed);
        deflater.finish();
        ByteArrayOutputStream baos = new ByteArrayOutputStream(uncompressed.length);
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            int len = deflater.deflate(buffer);
            baos.write(buffer, 0, len);
        }
        baos.close();
        return baos.toByteArray();
    }

    private static byte[] inflate(byte[] compressed) throws IOException,
            DataFormatException {

        Inflater inflater = new Inflater();
        inflater.setInput(compressed);
        inflater.finished();
        ByteArrayOutputStream baos = new ByteArrayOutputStream(compressed.length);
        byte[] buffer = new byte[1024];
        while (!inflater.finished()) {
            int len = inflater.inflate(buffer);
            baos.write(buffer, 0, len);
        }
        baos.close();
        return baos.toByteArray();
    }
}
