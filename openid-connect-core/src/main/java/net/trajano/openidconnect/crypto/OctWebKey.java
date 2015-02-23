package net.trajano.openidconnect.crypto;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)

public class OctWebKey extends JsonWebKey {

    public OctWebKey(String kid, JsonWebAlgorithm alg, byte[] keyBytes) {

        super(kid, KeyType.OCT, alg, KeyUse.ENC);
        k = Base64Url.encode(keyBytes);
    }

    private String k;
}
