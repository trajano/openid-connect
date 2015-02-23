package net.trajano.openidconnect.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RsaWebKey extends JsonWebKey {

    @XmlElement
    private String d;

    @XmlElement
    private String e;

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

}
