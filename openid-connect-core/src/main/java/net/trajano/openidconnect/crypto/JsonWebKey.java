package net.trajano.openidconnect.crypto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({ RsaWebKey.class, EcWebKey.class, OctWebKey.class })
public abstract class JsonWebKey {

    @XmlElement
    private final JsonWebAlgorithm alg;

    @XmlElement(name = "kid")
    private final String kid;

    @XmlElement
    private final KeyType kty;

    @XmlElement
    private final KeyUse use;

    public JsonWebKey(final String kid, final KeyType kty, final JsonWebAlgorithm alg, final KeyUse use) {

        this.kid = kid;
        this.alg = alg;
        this.kty = kty;
        this.use = use;
    }

    public JsonWebAlgorithm getAlg() {

        return alg;
    }

    public String getKid() {

        return kid;
    }

    public KeyType getKty() {

        return kty;
    }

    public KeyUse getUse() {

        return use;
    }
}
