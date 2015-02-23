package net.trajano.openidconnect.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.json.JsonObjectBuilder;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class OctWebKey extends JsonWebKey {

    private String k;

    
    public String getK() {
    
        return k;
    }

    
    public void setK(String k) {
    
        this.k = k;
    }

    @Override
    public Key toJcaKey() throws GeneralSecurityException {

        // TODO Auto-generated method stub
        return null;
    }


    @Override
    protected void addToJsonObject(JsonObjectBuilder keyBuilder) {

        keyBuilder.add("k", k);
        
    }
}
