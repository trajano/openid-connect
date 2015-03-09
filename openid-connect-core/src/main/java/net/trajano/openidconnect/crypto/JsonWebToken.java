package net.trajano.openidconnect.crypto;

import java.io.IOException;

/**
 * The JSON Web Token. It is comprised of a header that is a Base64url encoded
 * JSON followed by 1 to many Base64url encoded payloads joined by '.'
 * character. This class is immutable
 *
 * @author Archimedes
 */
public class JsonWebToken {

    /**
     * Constant for the "none" algorithm.
     */
    public static final String ALG_NONE = "none";

    /**
     * <p>
     * "alg" (Algorithm) Header Parameter
     * </p>
     * <p>
     * This parameter has the same meaning, syntax, and processing rules as the
     * alg Header Parameter defined in Section 4.1.1 of [JWS], except that the
     * Header Parameter identifies the cryptographic algorithm used to encrypt
     * or determine the value of the Content Encryption Key (CEK). The encrypted
     * content is not usable if the alg value does not represent a supported
     * algorithm, or if the recipient does not have a key that can be used with
     * that algorithm.
     * </p>
     * <p>
     * A list of defined alg values for this use can be found in the IANA JSON
     * Web Signature and Encryption Algorithms registry defined in [JWA]; the
     * initial contents of this registry are the values defined in Section 4.1
     * of the JSON Web Algorithms (JWA) [JWA] specification.
     * </p>
     */
    private final String alg;

    /**
     * <p>
     * "enc" (Encryption Algorithm) Header Parameter
     * </p>
     * <p>
     * The enc (encryption algorithm) Header Parameter identifies the content
     * encryption algorithm used to perform authenticated encryption on the
     * Plaintext to produce the Ciphertext and the Authentication Tag. This
     * algorithm MUST be an AEAD algorithm with a specified key length. The
     * encrypted content is not usable if the enc value does not represent a
     * supported algorithm. enc values should either be registered in the IANA
     * JSON Web Signature and Encryption Algorithms registry defined in [JWA] or
     * be a value that contains a Collision-Resistant Name. The enc value is a
     * case-sensitive ASCII string containing a StringOrURI value. This Header
     * Parameter MUST be present and MUST be understood and processed by
     * implementations.
     * </p>
     * <p>
     * A list of defined enc values for this use can be found in the IANA JSON
     * Web Signature and Encryption Algorithms registry defined in [JWA]; the
     * initial contents of this registry are the values defined in Section 5.1
     * of the JSON Web Algorithms (JWA) [JWA] specification.
     * </p>
     */
    private final String enc;

    private final String joseHeaderEncoded;

    private final byte[][] payloads;

    /**
     * <p>
     * "zip" (Compression Algorithm) Header Parameter
     * <p>
     * <p>
     * The zip (compression algorithm) applied to the Plaintext before
     * encryption, if any. The zip value defined by this specification is:
     * </p>
     * <ul>
     * <li>DEF - Compression with the DEFLATE [RFC1951] algorithm
     * </ul>
     * <p>
     * Other values MAY be used. Compression algorithm values can be registered
     * in the IANA JSON Web Encryption Compression Algorithm registry defined in
     * [JWA]. The zip value is a case-sensitive string. If no zip parameter is
     * present, no compression is applied to the Plaintext before encryption.
     * When used, this Header Parameter MUST be integrity protected; therefore,
     * it MUST occur only within the JWE Protected Header. Use of this Header
     * Parameter is OPTIONAL. This Header Parameter MUST be understood and
     * processed by implementations.
     * </p>
     */
    private final String zip;

    /**
     * "kid" (Key ID) Header Parameter
     * <p>
     * This parameter has the same meaning, syntax, and processing rules as the
     * kid Header Parameter defined in Section 4.1.4 of [JWS], except that the
     * key hint references the public key to which the JWE was encrypted; this
     * can be used to determine the private key needed to decrypt the JWE. This
     * parameter allows originators to explicitly signal a change of key to JWE
     * recipients.
     */
    private final String kid;

    public JsonWebToken(final JoseHeader joseHeader, final byte[][] payloads) {

        joseHeaderEncoded = new String(joseHeader.getEncoded());
        alg = joseHeader.getAlg();
        enc = joseHeader.getEnc();
        kid = joseHeader.getKid();
        zip = joseHeader.getZip();
        this.payloads = payloads;
    }

    public JsonWebToken(final String jwt) throws IOException {

        final String[] tokens = jwt.split("\\.");

        joseHeaderEncoded = tokens[0];
        final JoseHeader joseHeader = new JoseHeader(Encoding.base64DecodeToString(joseHeaderEncoded));

        alg = joseHeader.getAlg();
        enc = joseHeader.getEnc();
        kid = joseHeader.getKid();
        zip = joseHeader.getZip();

        payloads = new byte[tokens.length - 1][];
        for (int i = 1; i < tokens.length; ++i) {
            payloads[i - 1] = Encoding.base64urlDecode(tokens[i]);
        }

    }

    public String getKid() {

        return kid;
    }

    public String getAlg() {

        return alg;
    }

    public String getEnc() {

        return enc;
    }

    /**
     * This retrieves the JOSE header. Please note that this is an expensive
     * process because it will perform decoding of the data. The JOSE header
     * returned may be mutable but it is not associated with this object.
     *
     * @return JOSE header
     */
    public JoseHeader getJoseHeader() {

        return new JoseHeader(Encoding.base64DecodeToString(joseHeaderEncoded));
    }

    /**
     * Gets the encoded JOSE Header as it was provided.
     *
     * @return
     */
    public String getJoseHeaderEncoded() {

        return joseHeaderEncoded;
    }

    public int getNumberOfPayloads() {

        return payloads.length;
    }

    public byte[] getPayload(final int i) {

        return payloads[i];
    }

    public String getZip() {

        return zip;
    }

    /**
     * Builds the serialized JWT.
     */
    @Override
    public String toString() {

        final StringBuilder b = new StringBuilder(joseHeaderEncoded);
        for (final byte[] payload : payloads) {
            b.append('.')
                    .append(Encoding.base64Encode(payload));
        }
        return b.toString();

    }

}
