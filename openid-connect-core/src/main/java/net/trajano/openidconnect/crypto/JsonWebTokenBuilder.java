package net.trajano.openidconnect.crypto;

import static net.trajano.openidconnect.crypto.JsonWebToken.ALG_NONE;

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

    /**
     * Algorithm applied to the JWT. Defaults to none.
     */
    private String alg = JsonWebToken.ALG_NONE;

    private boolean compressed;

    private final JsonWebTokenCrypto crypto = JcaJsonWebTokenCrypto.getInstance();

    /**
     * Encryption algorithm.
     */
    private String enc;

    /**
     * Json Web Key to apply. If it is an encryption one it will do JWE else it
     * will do JWS.
     */
    private JsonWebKey jwk;

    private final SecureRandom random = new SecureRandom();

    /**
     * The actual payload.
     */
    private byte[] uncompressedPayloadBytes;

    /**
     * Sets the algorithm. This should be done after setting the jwk/jwks.
     * 
     * @param alg2
     * @return
     */
    public JsonWebTokenBuilder alg(final String alg2) {

        alg = alg2;
        return this;
    }

    public JsonWebToken build() throws IOException,
            GeneralSecurityException {

        final JoseHeader header = new JoseHeader();
        header.setAlg(alg);

        byte[] payloadBytes = uncompressedPayloadBytes;
        if (compressed) {
            header.setZip("DEF");
            payloadBytes = crypto.deflate(payloadBytes);
        }

        if (ALG_NONE.equals(alg) && jwk == null) {
            final byte[][] payloads = new byte[1][];
            payloads[0] = payloadBytes;
            return new JsonWebToken(header, payloads);
        }

        if (ALG_NONE.equals(alg) && jwk != null) {
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

    public JsonWebTokenBuilder compress(final boolean compressed) {

        this.compressed = compressed;
        return this;
    }

    public JsonWebTokenBuilder enc(final String enc2) {

        enc = enc2;
        return this;
    }

    /**
     * Sets the JSON Web Key. This will also set the algorithm if it is defined
     * in the key.
     *
     * @param jwk
     * @return
     */
    public JsonWebTokenBuilder jwk(final JsonWebKey jwk) {

        this.jwk = jwk;
        if (jwk.getAlg() != null) {
            alg = jwk.getAlg();
        }
        return this;
    }

    /**
     * Chooses a random key from the JWKS.
     *
     * @param jwks
     *            JWK set
     * @return
     */
    public JsonWebTokenBuilder jwk(final JsonWebKeySet jwks) {

        final JsonWebKey[] keys = jwks.getKeys();

        jwk = keys[random.nextInt(keys.length)];
        return this;
    }

    public JsonWebTokenBuilder payload(final byte[] payloadBytes) {

        uncompressedPayloadBytes = payloadBytes;
        return this;
    }

    public JsonWebTokenBuilder payload(final JsonObject jsonObject) {

        return payload(jsonObject.toString());
    }

    public JsonWebTokenBuilder payload(final String s) {

        return payload(s.getBytes(CharSets.UTF8));
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
}
