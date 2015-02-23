package net.trajano.openidconnect.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RsaWebKey extends JsonWebKey {

    @XmlElement
    private final String d;

    @XmlElement
    private final String e;

    @XmlElement
    private final String n;

    @XmlElement
    private final String p;

    public RsaWebKey(final String kid, final KeyPair keyPair) {

        super(kid, KeyType.RSA, JsonWebAlgorithm.RS256, KeyUse.ENC);
        final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        e = Base64Url.encodeUint(publicKey.getPublicExponent());
        n = Base64Url.encodeUint(publicKey.getModulus());
        final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        d = Base64Url.encodeUint(privateKey.getPrivateExponent());
        // TODO check this may be wrong.
        p = Base64Url.encodeUint(privateKey.getModulus());
        System.out.println(e);
    }

    public RsaWebKey(final String kid, final RSAPublicKey publicKey) {

        super(kid, KeyType.RSA, JsonWebAlgorithm.RS256, KeyUse.SIG);
        e = Base64Url.encodeUint(publicKey.getPublicExponent());
        n = Base64Url.encodeUint(publicKey.getModulus());
        d = null;
        p = null;

    }

    public BigInteger getExponent() {

        return Base64Url.decodeUint(e);
    }

    public BigInteger getFirstPrimeFactor() {

        return Base64Url.decodeUint(p);
    }

    public BigInteger getModulus() {

        return Base64Url.decodeUint(n);
    }

    public BigInteger getPrivateExponent() {

        return Base64Url.decodeUint(d);
    }
}
