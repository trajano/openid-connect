package net.trajano.openidconnect.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({ RsaWebKey.class, EcWebKey.class, OctWebKey.class })
public abstract class JsonWebKey {

    @XmlElement
    private JsonWebAlgorithm alg;

    @XmlElement(name = "kid")
    private String kid;

    @XmlElement
    private KeyType kty;

    @XmlElement
    private KeyUse use;

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

    public void setAlg(final JsonWebAlgorithm alg) {

        this.alg = alg;
    }

    public void setKid(final String kid) {

        this.kid = kid;
    }

    public void setKty(final KeyType kty) {

        this.kty = kty;
    }

    public void setUse(final KeyUse use) {

        this.use = use;
    }

    /**
     * Converts the JSON Web key to the JCA key.
     * 
     * @return
     */
    public abstract Key toJcaKey() throws GeneralSecurityException;
}
