package net.trajano.openidconnect.auth;

import java.net.URI;

import javax.ws.rs.core.MediaType;

import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.crypto.JsonWebKey;

public class JoseHeader {

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
    private JsonWebAlgorithm alg = JsonWebAlgorithm.none;

    /**
     * "crit" (Critical) Header Parameter
     * <p>
     * This parameter has the same meaning, syntax, and processing rules as the
     * crit Header Parameter defined in Section 4.1.11 of [JWS], except that
     * Header Parameters for a JWE are being referred to, rather than Header
     * Parameters for a JWS.
     */
    private String[] crit;

    /**
     * "cty" (Content Type) Header Parameter
     * <p>
     * The "cty" (content type) Header Parameter is used by JWS applications to
     * declare the MIME Media Type [IANA.MediaTypes] of the secured <b>content
     * (the payload)</b>. This is intended for use by the application when more
     * than one kind of object could be present in the JWS payload; the
     * application can use this value to disambiguate among the different kinds
     * of objects that might be present. It will typically not be used by
     * applications when the kind of object is already known. This parameter is
     * ignored by JWS implementations; any processing of this parameter is
     * performed by the JWS application. Use of this Header Parameter is
     * OPTIONAL.
     * </p>
     * <p>
     * Per RFC 2045 [RFC2045], all media type values, subtype values, and
     * parameter names are case-insensitive. However, parameter values are
     * case-sensitive unless otherwise specified for the specific parameter. *
     * </p>
     * <p>
     * To keep messages compact in common situations, it is RECOMMENDED that
     * producers omit an "application/" prefix of a media type value in a "cty"
     * Header Parameter when no other '/' appears in the media type value. A
     * recipient using the media type value MUST treat it as if "application/"
     * were prepended to any "cty" value not containing a '/'. For instance, a
     * "cty" value of "example" SHOULD be used to represent the
     * "application/example" media type; whereas, the media type
     * "application/example;part="1/2"" cannot be shortened to
     * "example;part="1/2"".
     * </p>
     */
    private MediaType cty;

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
    private JsonWebAlgorithm enc;

    /**
     * "jku" (JWK Set URL) Header Parameter
     * <p>
     * This parameter has the same meaning, syntax, and processing rules as the
     * jku Header Parameter defined in Section 4.1.2 of [JWS], except that the
     * JWK Set resource contains the public key to which the JWE was encrypted;
     * this can be used to determine the private key needed to decrypt the JWE.
     */
    private URI jku;

    /**
     * <p>
     * "jwk" (JSON Web Key) Header Parameter
     * </p>
     * <p>
     * This parameter has the same meaning, syntax, and processing rules as the
     * jwk Header Parameter defined in Section 4.1.3 of [JWS], except that the
     * key is the public key to which the JWE was encrypted; this can be used to
     * determine the private key needed to decrypt the JWE.
     * </p>
     */
    private JsonWebKey jwk;

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
    private String kid;

    public JsonWebAlgorithm getAlg() {

        return alg;
    }

    public void setAlg(JsonWebAlgorithm alg) {

        this.alg = alg;
    }

    public String[] getCrit() {

        return crit;
    }

    public void setCrit(String[] crit) {

        this.crit = crit;
    }

    public MediaType getCty() {

        return cty;
    }

    public void setCty(MediaType cty) {

        this.cty = cty;
    }

    public JsonWebAlgorithm getEnc() {

        return enc;
    }

    public void setEnc(JsonWebAlgorithm enc) {

        this.enc = enc;
    }

    public URI getJku() {

        return jku;
    }

    public void setJku(URI jku) {

        this.jku = jku;
    }

    public JsonWebKey getJwk() {

        return jwk;
    }

    public void setJwk(JsonWebKey jwk) {

        this.jwk = jwk;
    }

    public String getKid() {

        return kid;
    }

    public void setKid(String kid) {

        this.kid = kid;
    }

    public MediaType getTyp() {

        return typ;
    }

    public void setTyp(MediaType typ) {

        this.typ = typ;
    }

    public String getX5c() {

        return x5c;
    }

    public void setX5c(String x5c) {

        this.x5c = x5c;
    }

    public String getX5t() {

        return x5t;
    }

    public void setX5t(String x5t) {

        this.x5t = x5t;
    }

    public String getX5t_s256() {

        return x5t_s256;
    }

    public void setX5t_s256(String x5t_s256) {

        this.x5t_s256 = x5t_s256;
    }

    public URI getX5u() {

        return x5u;
    }

    public void setX5u(URI x5u) {

        this.x5u = x5u;
    }

    public String getZip() {

        return zip;
    }

    public void setZip(String zip) {

        this.zip = zip;
    }

    /**
     * "typ" (Type) Header Parameter
     * <p>
     * The "typ" (type) Header Parameter is used by JWS applications to declare
     * the MIME Media Type [IANA.MediaTypes] of this <b>complete JWS</b>. This
     * is intended for use by the application when more than one kind of object
     * could be present in an application data structure that can contain a JWS;
     * the application can use this value to disambiguate among the different
     * kinds of objects that might be present. It will typically not be used by
     * applications when the kind of object is already known. This parameter is
     * ignored by JWS implementations; any processing of this parameter is
     * performed by the JWS application. Use of this Header Parameter is
     * OPTIONAL.
     * </p>
     * <p>
     * Per RFC 2045 [RFC2045], all media type values, subtype values, and
     * parameter names are case-insensitive. However, parameter values are
     * case-sensitive unless otherwise specified for the specific parameter.
     * </p>
     * <p>
     * To keep messages compact in common situations, it is RECOMMENDED that
     * producers omit an "application/" prefix of a media type value in a "typ"
     * Header Parameter when no other '/' appears in the media type value. A
     * recipient using the media type value MUST treat it as if "application/"
     * were prepended to any "typ" value not containing a '/'. For instance, a
     * "typ" value of "example" SHOULD be used to represent the
     * "application/example" media type; whereas, the media type
     * "application/example;part="1/2"" cannot be shortened to
     * "example;part="1/2"".
     * </p>
     * <p>
     * The "typ" value "JOSE" can be used by applications to indicate that this
     * object is a JWS or JWE using the JWS Compact Serialization or the JWE
     * Compact Serialization. The "typ" value "JOSE+JSON" can be used by
     * applications to indicate that this object is a JWS or JWE using the JWS
     * JSON Serialization or the JWE JSON Serialization. Other type values can
     * also be used by applications.
     */
    private MediaType typ;

    /**
     * "x5c" (X.509 Certificate Chain) Header Parameter
     *
     <p>
     * This parameter has the same meaning, syntax, and processing rules as the
     * x5c Header Parameter defined in Section 4.1.6 of [JWS], except that the
     * X.509 public key certificate or certificate chain [RFC5280] contains the
     * public key to which the JWE was encrypted; this can be used to determine
     * the private key needed to decrypt the JWE.
     * </p>
     * <p>
     * See Appendix B of [JWS] for an example x5c value.
     * </p>
     */
    private String x5c;

    /**
     * "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter
     * <p>
     * This parameter has the same meaning, syntax, and processing rules as the
     * x5t Header Parameter defined in Section 4.1.7 of [JWS], except that the
     * certificate referenced by the thumbprint contains the public key to which
     * the JWE was encrypted; this can be used to determine the private key
     * needed to decrypt the JWE. Note that certificate thumbprints are also
     * sometimes known as certificate fingerprints.
     */
    private String x5t;

    /**
     * "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter This
     * parameter has the same meaning, syntax, and processing rules as the
     * x5t#S256 Header Parameter defined in Section 4.1.8 of [JWS], except that
     * the certificate referenced by the thumbprint contains the public key to
     * which the JWE was encrypted; this can be used to determine the private
     * key needed to decrypt the JWE. Note that certificate thumbprints are also
     * sometimes known as certificate fingerprints.
     */
    private String x5t_s256;

    /**
     * "x5u" (X.509 URL) Header Parameter This parameter has the same meaning,
     * syntax, and processing rules as the x5u Header Parameter defined in
     * Section 4.1.5 of [JWS], except that the X.509 public key certificate or
     * certificate chain [RFC5280] contains the public key to which the JWE was
     * encrypted; this can be used to determine the private key needed to
     * decrypt the JWE.
     */
    private URI x5u;

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
    private String zip;
}
