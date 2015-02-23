package net.trajano.openidconnect.crypto;

/**
 * JWKs can represent RSA [RFC3447] keys. In this case, the "kty" member value
 * is "RSA". The semantics of the parameters defined below are the same as those
 * defined in Sections 3.1 and 3.2 of RFC 3447.
 * 
 * @author Archimedes
 */
public class RsaPublicJsonWebKey extends JsonWebKey {

    /**
     * <p>
     * "n" (Modulus) Parameter
     * </p>
     * <p>
     * The "n" (modulus) member contains the modulus value for the RSA public
     * key. It is represented as a Base64urlUInt encoded value.
     * </p>
     * <p>
     * Note that implementers have found that some cryptographic libraries
     * prefix an extra zero-valued octet to the modulus representations they
     * return, for instance, returning 257 octets for a 2048 bit key, rather
     * than 256. Implementations using such libraries will need to take care to
     * omit the extra octet from the base64url encoded representation.
     * </p>
     */
    private String n;

    /**
     * <p>
     * "e" (Exponent) Parameter.
     * </p>
     * <p>
     * The "e" (exponent) member contains the exponent value for the RSA public
     * key. It is represented as a Base64urlUInt encoded value.
     * </p>
     * <p>
     * For instance, when representing the value 65537, the octet sequence to be
     * base64url encoded MUST consist of the three octets [1, 0, 1]; the
     * resulting representation for this value is "AQAB".
     * </p>
     */
    private String e;
}
