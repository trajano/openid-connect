package net.trajano.openidconnect.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.JsonObject;

import net.trajano.openidconnect.auth.JsonWebTokenBuilder;
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
        } else if (jsonWebToken.getEnc() == JsonWebAlgorithm.A128CBC_HS256) {
            final IvParameterSpec spec = new IvParameterSpec(initializationVector);
            contentCipher.init(Cipher.DECRYPT_MODE, contentEncryptionKey, spec);

        } else {
            final IvParameterSpec spec = new IvParameterSpec(initializationVector);
            contentCipher.init(Cipher.DECRYPT_MODE, contentEncryptionKey, spec);
        }
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(contentCipher.update(cipherText));
        baos.write(contentCipher.doFinal(authenticationTag));
        baos.close();
        final byte[] plaintext = baos.toByteArray();
        final boolean compress = "DEF".equals(jsonWebToken.getZip());
        if (compress) {
            return inflate(plaintext);
        } else {
            return plaintext;
        }
    }

    public static byte[] decrypt(final String jwe,
            final JsonWebKey jwk) throws IOException,
            GeneralSecurityException,
            DataFormatException {

        final JsonWebToken jsonWebToken = new JsonWebToken(jwe);
        return decrypt(jsonWebToken, jwk);
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

        JsonWebTokenBuilder b = new JsonWebTokenBuilder();
        b.payload(plaintext);
        b.jwk(jwk);
        b.alg(alg);
        b.enc(enc);
        b.compress(compress);
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

    private static byte[] inflate(final byte[] compressed) throws IOException {

        final Inflater inflater = new Inflater(false);
        inflater.setInput(compressed);
        inflater.finished();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream(compressed.length);
        final byte[] buffer = new byte[1024];
        try {
            while (!inflater.finished()) {
                int len;
                len = inflater.inflate(buffer);
                baos.write(buffer, 0, len);
            }
            baos.close();
            return baos.toByteArray();
        } catch (DataFormatException e) {
            throw new IOException(e);
        }
    }
}
