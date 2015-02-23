package net.trajano.openidconnect.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.json.JsonObjectBuilder;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class EcWebKey extends JsonWebKey {

    private String crv;

    private String x;

    
    public String getCrv() {
    
        return crv;
    }

    
    public void setCrv(String crv) {
    
        this.crv = crv;
    }

    
    public String getX() {
    
        return x;
    }

    
    public void setX(String x) {
    
        this.x = x;
    }

    
    public String getY() {
    
        return y;
    }

    
    public void setY(String y) {
    
        this.y = y;
    }

    private String y;

    @Override
    public Key toJcaKey() throws GeneralSecurityException {

        // TODO Auto-generated method stub
        return null;
    }


    @Override
    protected void addToJsonObject(JsonObjectBuilder keyBuilder) {

        // TODO Auto-generated method stub
        
    }

}
