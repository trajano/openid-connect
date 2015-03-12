package net.trajano.openidconnect.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.NONE)
public class JsonWebKeySet {

    private final Map<String, JsonWebKey> keys = new HashMap<>();
    private final Map<String, JsonWebKey> signingKeys = new HashMap<>();

    public void add(final JsonWebKey jwk) {

        keys.put(jwk.getKid(), jwk);
        if (jwk.getKty() == KeyType.RSA || jwk.getKty() == KeyType.EC) {
            signingKeys.put(jwk.getKid(), jwk);
        }
    }

    @XmlElement(name = "keys", required = true)
    public JsonWebKey[] getKeys() {

        return keys.values()
                .toArray(new JsonWebKey[0]);
    }
    

    public JsonWebKey[] getSigningKeys() {

        return signingKeys.values()
                .toArray(new JsonWebKey[0]);
    }


    public Key getKey(String kid) throws GeneralSecurityException {

        return getJwk(kid).toJcaKey();
    }

    public JsonWebKey getJwk(String kid) {

        return keys.get(kid);

    }
}
