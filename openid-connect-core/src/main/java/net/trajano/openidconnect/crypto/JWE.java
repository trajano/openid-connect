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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.JsonObject;

import net.trajano.openidconnect.auth.JoseHeader;
import net.trajano.openidconnect.internal.CharSets;

public class JWE {

    public static byte[] decrypt(final JsonWebToken jsonWebToken,
            final JsonWebKey jwk) throws IOException,
            GeneralSecurityException {

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

        final Cipher contentCipher = Cipher.getInstance(jsonWebToken.getEnc()
                .toJca());
        if (jsonWebToken.getEnc() == JsonWebAlgorithm.A128GCM || jsonWebToken.getEnc() == JsonWebAlgorithm.A256GCM) {
            final GCMParameterSpec spec = new GCMParameterSpec(authenticationTag.length * 8, initializationVector);
            contentCipher.init(Cipher.DECRYPT_MODE, contentEncryptionKey, spec);
            contentCipher.updateAAD(aad);
        } else {
            final IvParameterSpec spec = new IvParameterSpec(initializationVector);
            contentCipher.init(Cipher.DECRYPT_MODE, contentEncryptionKey, spec);
        }
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(contentCipher.update(cipherText));
        baos.write(contentCipher.doFinal(authenticationTag));
        baos.close();
        final byte[] plaintext = baos.toByteArray();
        try {
            final boolean compress = "DEF".equals(jsonWebToken.getZip());
            if (compress) {
                return inflate(plaintext);
            } else {
                return plaintext;
            }
        } catch (final DataFormatException e) {
            throw new IOException(e);
        }
    }

    public static byte[] decrypt(final String jwe,
            final JsonWebKey jwk) throws IOException,
            GeneralSecurityException,
            DataFormatException {

        final JsonWebToken jsonWebToken = new JsonWebToken(jwe);
        return decrypt(jsonWebToken, jwk);
    }

    private static byte[] deflate(final byte[] uncompressed) throws IOException {

        final Deflater deflater = new Deflater(9, false);
        deflater.setInput(uncompressed);
        deflater.finish();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream(uncompressed.length);
        final byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            final int len = deflater.deflate(buffer);
            baos.write(buffer, 0, len);
        }
        baos.close();
        return baos.toByteArray();
    }

    public static String encrypt(final byte[] plaintext,
            final JsonWebKey jwk,
            final JsonWebAlgorithm alg,
            final JsonWebAlgorithm enc) throws IOException,
            GeneralSecurityException {

        return encrypt(plaintext, jwk, alg, enc, false);
    }

    public static String encrypt(final byte[] plaintext,
            final JsonWebKey jwk,
            final JsonWebAlgorithm alg,
            final JsonWebAlgorithm enc,
            final boolean compress) throws IOException,
            GeneralSecurityException {

        final JoseHeader joseHeader = new JoseHeader();
        joseHeader.setAlg(alg);
        joseHeader.setEnc(enc);
        if (jwk.getKid() != null) {
            joseHeader.setKid(jwk.getKid());
        }
        joseHeader.setZip(compress ? "DEF" : null);
        final String encodedJoseHeader = Base64Url.encode(joseHeader.toString());
        final StringBuilder b = new StringBuilder(encodedJoseHeader);
        b.append('.');

        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.getBits());
        final SecretKey secretKey = keyGenerator.generateKey();

        final byte[] cek = secretKey.getEncoded();

        final Cipher cekCipher = Cipher.getInstance(alg.toJca());
        cekCipher.init(Cipher.ENCRYPT_MODE, jwk.toJcaKey());
        final byte[] encryptedCek = cekCipher.doFinal(cek);

        b.append(Base64Url.encode(encryptedCek));
        b.append('.');

        final SecureRandom random = new SecureRandom();
        final byte[] iv;
        final int authenticationTagBits = 128;
        final Cipher contentCipher = Cipher.getInstance(enc.toJca());
        if (joseHeader.getEnc() == JsonWebAlgorithm.A128GCM || joseHeader.getEnc() == JsonWebAlgorithm.A256GCM) {
            iv = new byte[96];
            random.nextBytes(iv);
            final GCMParameterSpec spec = new GCMParameterSpec(authenticationTagBits, iv);
            contentCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), spec);
            contentCipher.updateAAD(encodedJoseHeader.getBytes(CharSets.US_ASCII));
        } else {
            iv = new byte[16];
            random.nextBytes(iv);
            final IvParameterSpec spec = new IvParameterSpec(iv);
            contentCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), spec);
        }
        b.append(Base64Url.encode(iv));
        b.append('.');

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

    public static String encrypt(final JsonObject obj,
            final JsonWebKey jwk,
            final JsonWebAlgorithm alg,
            final JsonWebAlgorithm enc) throws IOException,
            GeneralSecurityException {

        return encrypt(obj.toString()
                .getBytes(CharSets.UTF8), jwk, alg, enc, false);
    }

    private static byte[] inflate(final byte[] compressed) throws IOException,
    DataFormatException {

        final Inflater inflater = new Inflater(false);
        inflater.setInput(compressed);
        inflater.finished();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream(compressed.length);
        final byte[] buffer = new byte[1024];
        while (!inflater.finished()) {
            final int len = inflater.inflate(buffer);
            baos.write(buffer, 0, len);
        }
        baos.close();
        return baos.toByteArray();
    }
}
