package net.trajano.openidconnect.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import javax.json.JsonObjectBuilder;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RsaWebKey extends JsonWebKey {

    public RsaWebKey() {

    }

    public RsaWebKey(String kid, RSAPublicKey publicKey) {

        setKid(kid);
        setUse(KeyUse.sig);
        n = (Base64Url.encodeUint(publicKey.getModulus()));
        e = (Base64Url.encodeUint(publicKey.getPublicExponent()));
    }

    @XmlElement
    private String d;

    /**
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
    @XmlElement
    private String e;

    /**
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
    @XmlElement
    private String n;

    @XmlElement
    private String p;

    public String getD() {

        return d;
    }

    public String getE() {

        return e;
    }

    public String getN() {

        return n;
    }

    public String getP() {

        return p;
    }

    public void setD(final String d) {

        this.d = d;
    }

    public void setE(final String e) {

        this.e = e;
    }

    public void setN(final String n) {

        this.n = n;
    }

    public void setP(final String p) {

        this.p = p;
    }

    @Override
    public Key toJcaKey() throws GeneralSecurityException {

        if (getUse() == KeyUse.sig) {
            final BigInteger modulus = Base64Url.decodeUint(n);
            final BigInteger publicExponent = Base64Url.decodeUint(e);
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        } else {
            // TODO later
            return null;
        }
    }

    @Override
    protected void addToJsonObject(JsonObjectBuilder keyBuilder) {

        if (getUse() == KeyUse.enc) {
            keyBuilder.add("d", d);
            keyBuilder.add("p", p);
        }
        keyBuilder.add("n", n);
        keyBuilder.add("e", e);

    }

}
