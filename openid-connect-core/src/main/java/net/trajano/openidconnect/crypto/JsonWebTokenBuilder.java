package net.trajano.openidconnect.crypto;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.json.JsonObject;

import net.trajano.openidconnect.internal.CharSets;
import net.trajano.openidconnect.internal.JcaJsonWebTokenCrypto;

/**
 * Used to build {@link JsonWebToken}. It will handle signing and encryption of
 * data as needed.
 * 
 * @author Archimedes
 */
public class JsonWebTokenBuilder {

    private final SecureRandom random = new SecureRandom();

    private final JsonWebTokenCrypto crypto = JcaJsonWebTokenCrypto.getInstance();

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
     * @param jwks JWK set
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
            payloadBytes = crypto.deflate(payloadBytes);
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
            return new JsonWebToken(header, crypto.buildJWSPayload(header, payloadBytes, jwk));
        }

        // JWE
        header.setEnc(enc);
        return new JsonWebToken(header, crypto.buildJWEPayload(header, payloadBytes, jwk));
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
