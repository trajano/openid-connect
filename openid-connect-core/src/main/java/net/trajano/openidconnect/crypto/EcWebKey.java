package net.trajano.openidconnect.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

import javax.json.JsonObjectBuilder;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class EcWebKey extends JsonWebKey {

    private String crv;

    /**
     *
     The "d" (ECC private key) member contains the Elliptic Curve private key
     * value. It is represented as the base64url encoding of the octet string
     * representation of the private key value, as defined in Section 2.3.7 of
     * SEC1 [SEC1]. The length of this octet string MUST be
     * ceiling(log-base-2(n)/8) octets (where n is the order of the curve).
     */
    private String d;

    private String x;

    private String y;

    @Override
    protected void addToJsonObject(final JsonObjectBuilder keyBuilder) {

        if (getUse() == KeyUse.enc) {
            keyBuilder.add("d", d);
        }
        keyBuilder.add("crv", crv);
        keyBuilder.add("x", x);
        keyBuilder.add("y", y);

    }

    public String getCrv() {

        return crv;
    }

    public String getD() {

        return d;
    }

    public String getX() {

        return x;
    }

    public String getY() {

        return y;
    }

    public void setCrv(final String crv) {

        this.crv = crv;
    }

    public void setD(final String d) {

        this.d = d;
    }

    public void setX(final String x) {

        this.x = x;
    }

    public void setY(final String y) {

        this.y = y;
    }

    @Override
    public Key toJcaKey() throws GeneralSecurityException {

        final KeyFactory keyFactory = KeyFactory.getInstance("EC");
        final ECParameterSpec ecParameterSpec = NamedEllipticCurve.valueOf(crv)
                .toECParameterSpec();
        if (getUse() == KeyUse.sig) {
            final ECPublicKeySpec keySpec = new ECPublicKeySpec(new ECPoint(Base64Url.decodeUint(x), Base64Url.decodeUint(y)), ecParameterSpec);
            return keyFactory.generatePublic(keySpec);
        } else {

            final ECPrivateKeySpec keySpec = new ECPrivateKeySpec(Base64Url.decodeUint(d), ecParameterSpec);
            return keyFactory.generatePrivate(keySpec);
        }

    }

}
