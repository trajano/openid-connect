package net.trajano.openidconnect.crypto;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class JsonWebKeySet {

    @XmlElement(required = true)
    private final Set<JsonWebKey> keys = new HashSet<>();

    public void add(final JsonWebKey jwk) {

        keys.add(jwk);
    }

    public Set<JsonWebKey> getKeys() {

        return Collections.unmodifiableSet(keys);
    }
}
