package net.trajano.openidconnect.crypto;

import java.security.interfaces.ECPublicKey;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class EcWebKey extends JsonWebKey {

    public EcWebKey(final String kid, final ECPublicKey publicKey) {

        super(kid, KeyType.EC, JsonWebAlgorithm.ES256, KeyUse.SIG);
    }

    private String crv;

}
