package net.trajano.openidconnect.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class EcWebKey extends JsonWebKey {

    private String crv;

    @Override
    public Key toJcaKey() throws GeneralSecurityException {

        // TODO Auto-generated method stub
        return null;
    }

}
