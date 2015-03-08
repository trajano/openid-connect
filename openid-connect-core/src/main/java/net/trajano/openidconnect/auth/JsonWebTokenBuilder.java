package net.trajano.openidconnect.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.zip.Deflater;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.JsonObject;

import net.trajano.openidconnect.crypto.Base64Url;
import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.crypto.JsonWebToken;
import net.trajano.openidconnect.internal.CharSets;

/**
 * Used to build {@link JsonWebToken}
 * 
 * @author Archimedes
 */
public class JsonWebTokenBuilder {

    private final SecureRandom random = new SecureRandom();

    /**
     * The actual payload.
     */
    private byte[] uncompressedPayloadBytes;

    /**
     * Algorithm applied to the JWT. Defaults to none.
     */
    private JsonWebAlgorithm alg = JsonWebAlgorithm.none;

    /**
     * Encryption algorithm.
     */
    private JsonWebAlgorithm enc;

    /**
     * Json Web Key to apply. If it is an encryption one it will do JWE else it
     * will do JWS.
     */
    private JsonWebKey jwk;

    private boolean compressed;

    public JsonWebTokenBuilder payload(JsonObject jsonObject) {

        return payload(jsonObject.toString());
    }

    public JsonWebTokenBuilder payload(String s) {

        return payload(s.getBytes(CharSets.UTF8));
    }

    public JsonWebTokenBuilder payload(byte[] payloadBytes) {

        this.uncompressedPayloadBytes = payloadBytes;
        return this;
    }

    /**
     * Sets the JSON Web Key. This will also set the algorithm if it is defined
     * in the key.
     * 
     * @param jwk
     * @return
     */
    public JsonWebTokenBuilder jwk(JsonWebKey jwk) {

        this.jwk = jwk;
        if (jwk.getAlg() != null) {
            alg = jwk.getAlg();
        }
        return this;
    }

    /**
     * Chooses a random key from the JWKS.
     * 
     * @param jwk
     * @return
     */
    public JsonWebTokenBuilder jwk(JsonWebKeySet jwks) {

        final JsonWebKey[] keys = jwks.getKeys();

        this.jwk = keys[random.nextInt(keys.length)];
        return this;
    }

    public JsonWebToken build() throws IOException,
            GeneralSecurityException {

        JoseHeader header = new JoseHeader();
        header.setAlg(alg);

        byte[] payloadBytes = uncompressedPayloadBytes;
        if (compressed) {
            header.setZip("DEF");
            payloadBytes = deflate(payloadBytes);
        }

        if (alg == JsonWebAlgorithm.none && jwk == null) {
            final byte[][] payloads = new byte[1][];
            payloads[0] = payloadBytes;
            return new JsonWebToken(header, payloads);
        }

        if (alg == JsonWebAlgorithm.none && jwk != null) {
            throw new IOException("JWK must not be defined for any alg that is none");
        }

        if (jwk == null) {
            throw new IOException("JWK must be defined for any alg that is not none");
        }

        if (jwk.getKid() != null) {
            header.setKid(jwk.getKid());
        } else {
            header.setJwk(jwk);
        }

        if (enc == null) {
            final byte[][] payloads = new byte[2][];
            payloads[0] = payloadBytes;
            payloads[1] = sign(header, payloadBytes);
            return new JsonWebToken(header, payloads);
        }

        // JWE
        header.setEnc(enc);
        return new JsonWebToken(header, buildEncryptedPayload(header, payloadBytes));
    }

    private byte[][] buildEncryptedPayload(JoseHeader joseHeader,
            byte[] payloadBytes) throws IOException,
            GeneralSecurityException {

        final byte[][] payloads = new byte[4][];

        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.getBits());
        final SecretKey secretKey = keyGenerator.generateKey();

        final byte[] cek = secretKey.getEncoded();

        final Cipher cekCipher = Cipher.getInstance(alg.toJca());
        cekCipher.init(Cipher.ENCRYPT_MODE, jwk.toJcaKey());
        final byte[] encryptedCek = cekCipher.doFinal(cek);

        payloads[0] = encryptedCek;

        final byte[] iv;
        final int authenticationTagBits = 128;
        final Cipher contentCipher = Cipher.getInstance(enc.toJca());

        if (enc == JsonWebAlgorithm.A128GCM || enc == JsonWebAlgorithm.A256GCM) {
            iv = new byte[96];
            random.nextBytes(iv);
            final GCMParameterSpec spec = new GCMParameterSpec(authenticationTagBits, iv);
            contentCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), spec);
            contentCipher.updateAAD(joseHeader.getEncoded());
        } else {
            iv = new byte[16];
            random.nextBytes(iv);
            final IvParameterSpec spec = new IvParameterSpec(iv);
            contentCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), spec);
        }
        payloads[1] = iv;

        final ByteBuffer cipherTextAndAuthenticationTag = ByteBuffer.wrap(contentCipher.doFinal(payloadBytes));

        payloads[2] = new byte[cipherTextAndAuthenticationTag.capacity() - authenticationTagBits / 8];
        payloads[3] = new byte[authenticationTagBits / 8];

        System.out.println(cipherTextAndAuthenticationTag.capacity());
        System.out.println(payloads[2].length);
        System.out.println(payloads[3].length);
        cipherTextAndAuthenticationTag.get(payloads[2])
                .get(payloads[3]);
        System.out.println(Base64Url.encode(payloads[2]));
        return payloads;
    }

    private byte[] sign(JoseHeader header,
            byte[] payloadBytes) throws GeneralSecurityException {

        final StringBuilder b = new StringBuilder(Base64Url.encode(header.toString())).append('.')
                .append(Base64Url.encode(payloadBytes));

        final Signature signature = Signature.getInstance(alg.toJca());
        signature.initSign((PrivateKey) jwk.toJcaKey());
        signature.update(b.toString()
                .getBytes(CharSets.US_ASCII));
        return signature.sign();
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

    /**
     * Gets the string representation of the JWT so far.
     */
    @Override
    public String toString() {

        try {
            return build().toString();
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public JsonWebTokenBuilder alg(JsonWebAlgorithm alg2) {

        this.alg = alg2;
        return this;
    }

    public JsonWebTokenBuilder compress(boolean compressed) {

        this.compressed = compressed;
        return this;
    }

    public JsonWebTokenBuilder enc(JsonWebAlgorithm enc2) {

        this.enc = enc2;
        return this;
    }
}
