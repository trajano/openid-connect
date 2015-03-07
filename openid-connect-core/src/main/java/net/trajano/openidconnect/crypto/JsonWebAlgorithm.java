package net.trajano.openidconnect.crypto;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.annotation.XmlEnumValue;

/**
 * <p>
 * This maps the algorithms to their JCA counterparts.
 * </p>
 * See Appendix A & B of
 * http://self-issued.info/docs/draft-ietf-jose-json-web-algorithms-00.html.
 */
public enum JsonWebAlgorithm {
    /**
     * Advanced Encryption Standard (AES) using 128 bit keys in Galois/Counter
     * Mode.
     */
    A128GCM("AES/GCM/NoPadding", 128),
    /**
     * Advanced Encryption Standard (AES) Key Wrap Algorithm RFC 3394 [RFC3394]
     * using 128 bit keys.
     */
    A128KW(null, 128),
    /**
     * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
     * Chaining mode.
     */
    A256CBC("AES/CBC/PKCS5Padding", 256),
    /**
     * Advanced Encryption Standard (AES) using 256 bit keys in Galois/Counter
     * Mode. Note this is only available from JDK8 onwards or Bouncy Castle.
     */
    A256GCM("AES/GCM/NoPadding", 256),
    /**
     * Advanced Encryption Standard (AES) Key Wrap Algorithm RFC 3394 [RFC3394]
     * using 256 bit keys.
     */
    A256KW(null, 256),
    /**
     * Elliptic Curve Diffie-Hellman Ephemeral Static.
     */
    @XmlEnumValue("ECDH-ES")
    ECDH_ES(null, 0),
    /**
     * ECDSA using P-256 curve and SHA-256 hash algorithm.
     */
    ES256("SHA256withECDSA", 256),
    /**
     * ECDSA using P-384 curve and SHA-384 hash algorithm.
     */
    ES384("SHA384withECDSA", 384),

    /**
     * ECDSA using P-521 curve and SHA-512 hash algorithm.
     */
    ES512("SHA512withECDSA", 512),
    /**
     * HMAC using SHA-256 hash algorithm.
     */
    HS256("HmacSHA256", 256),
    /**
     * HMAC using SHA-384 hash algorithm.
     */
    HS384("HmacSHA384", 384),
    /**
     * HMAC using SHA-512 hash algorithm.
     */
    HS512("HmacSHA512", 512),
    /**
     * Special case where the value is sent unencrypted.
     */
    none(null, 0),
    /**
     * RSA using SHA-256 hash algorithm.
     */
    RS256("SHA256withRSA", 256),
    /**
     * RSA using SHA-384 hash algorithm.
     */
    RS384("SHA384withRSA", 384),
    /**
     * RSA using SHA-512 hash algorithm.
     */
    RS512("SHA512withRSA", 512),
    /**
     * RSA using Optimal Asymmetric Encryption Padding (OAEP).
     */
    @XmlEnumValue("RSA-OAEP")
    RSA_OAEP("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", 0),
    /**
     * RSA using RSA-PKCS1-1.5 padding.
     */
    RSA1_5("RSA/ECB/PKCS1Padding", 0);

    private static final Map<String, JsonWebAlgorithm> REVERSE = new HashMap<>();

    /**
     * Symettric algorithms with JCA support.
     */
    public static final JsonWebAlgorithm[] SYMETTRIC_WITH_JCA = { A128GCM, A256CBC, A256GCM };

    static {
        for (final JsonWebAlgorithm jwa : EnumSet.allOf(JsonWebAlgorithm.class)) {
            if (jwa.jcaAlgorithm != null) {
                REVERSE.put(jwa.jcaAlgorithm, jwa);
            }
        }
    }

    public static JsonWebAlgorithm fromJca(final String jcaAlgorithm) {

        return REVERSE.get(jcaAlgorithm);
    }

    /**
     * JCA Algorithm.
     */
    private final String jcaAlgorithm;

    /**
     * Number of bits for the keys used in the algorithm.
     */
    private final int bits;

    /**
     * Assigns a JCA Algorithm to the JWA.
     *
     * @param jcaAlgorithm
     *            JCA algorithm
     */
    private JsonWebAlgorithm(final String jcaAlgorithm, int bits) {

        this.jcaAlgorithm = jcaAlgorithm;
        this.bits = bits;
    }

    /**
     * Returns the JCA Algorithm Name.
     *
     * @return JCA Algorithm Name.
     */
    public String toJca() {

        return jcaAlgorithm;
    }

    /**
     * Returns the number of bits. JCA algorithm names do not indicate the
     * number of bits unlike JWA.
     * 
     * @return
     */
    public int getBits() {

        return bits;
    }
}
