package net.trajano.openidconnect.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
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

        setKty(KeyType.RSA);
    }

    public RsaWebKey(String kid, RSAPublicKey publicKey) {

        setKty(KeyType.RSA);
        setKid(kid);
        setUse(KeyUse.sig);
        n = (Encoding.base64EncodeUint(publicKey.getModulus()));
        e = (Encoding.base64EncodeUint(publicKey.getPublicExponent()));
    }

    public RsaWebKey(String kid, RSAPrivateCrtKey privateKey) {

        setKty(KeyType.RSA);
        setKid(kid);
        setUse(KeyUse.enc);
        n = (Encoding.base64EncodeUint(privateKey.getModulus()));
        e = (Encoding.base64EncodeUint(privateKey.getPublicExponent()));
        p = (Encoding.base64EncodeUint(privateKey.getPrimeP()));
        q = (Encoding.base64EncodeUint(privateKey.getPrimeQ()));
        dp = (Encoding.base64EncodeUint(privateKey.getPrimeExponentP()));
        dq = (Encoding.base64EncodeUint(privateKey.getPrimeExponentQ()));
        d = (Encoding.base64EncodeUint(privateKey.getPrivateExponent()));
        qi = (Encoding.base64EncodeUint(privateKey.getCrtCoefficient()));

    }

    /**
     * The "d" (private exponent) member contains the private exponent value for
     * the RSA private key. It is represented as a Base64urlUInt encoded value.
     */
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

    /**
     * 
     The "p" (first prime factor) member contains the first prime factor. It
     * is represented as a Base64urlUInt encoded value.
     */
    @XmlElement
    private String p;

    /**
     * 
     The "q" (second prime factor) member contains the second prime factor. It
     * is represented as a Base64urlUInt encoded value.
     */
    @XmlElement
    private String q;

    /**
     * The "dp" (first factor CRT exponent) member contains the Chinese
     * Remainder Theorem (CRT) exponent of the first factor. It is represented
     * as a Base64urlUInt encoded value.
     */
    @XmlElement
    private String dp;

    /**
     * The "dq" (second factor CRT exponent) member contains the Chinese
     * Remainder Theorem (CRT) exponent of the second factor. It is represented
     * as a Base64urlUInt encoded value.
     */
    @XmlElement
    private String dq;

    public String getD() {

        return d;
    }

    /**
     * The "qi" (first CRT coefficient) member contains the Chinese Remainder
     * Theorem (CRT) coefficient of the second factor. It is represented as a
     * Base64urlUInt encoded value.
     */
    @XmlElement
    private String qi;

    public String getE() {

        return e;
    }

    public String getQ() {

        return q;
    }

    public void setQ(String q) {

        this.q = q;
    }

    public String getDp() {

        return dp;
    }

    public void setDp(String dp) {

        this.dp = dp;
    }

    public String getDq() {

        return dq;
    }

    public void setDq(String dq) {

        this.dq = dq;
    }

    public String getQi() {

        return qi;
    }

    public void setQi(String qi) {

        this.qi = qi;
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
    public PublicKey toJcaPublicKey() throws GeneralSecurityException {

        final BigInteger modulus = Encoding.base64urlDecodeUint(n);
        final BigInteger publicExponent = Encoding.base64urlDecodeUint(e);
        return KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
    }

    @Override
    public Key toJcaKey() throws GeneralSecurityException {

        final BigInteger modulus = Encoding.base64urlDecodeUint(n);
        final BigInteger publicExponent = Encoding.base64urlDecodeUint(e);
        if (getUse() == KeyUse.sig || d == null) {
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        } else {

            final BigInteger privateExponent = Encoding.base64urlDecodeUint(d);
            final BigInteger primeP = Encoding.base64urlDecodeUint(p);
            final BigInteger primeQ = Encoding.base64urlDecodeUint(q);
            final BigInteger primeExponentP = Encoding.base64urlDecodeUint(dp);
            final BigInteger primeExponentQ = Encoding.base64urlDecodeUint(dq);
            final BigInteger crtCoefficent = Encoding.base64urlDecodeUint(qi);
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficent));
        }

    }

    @Override
    protected void addToJsonObject(JsonObjectBuilder keyBuilder) {

        if (getUse() == KeyUse.enc) {
            keyBuilder.add("d", d);
            keyBuilder.add("p", p);
            keyBuilder.add("dp", dp);
            keyBuilder.add("dq", dq);
            keyBuilder.add("qi", qi);
        }
        keyBuilder.add("n", n);
        keyBuilder.add("e", e);

    }

}
