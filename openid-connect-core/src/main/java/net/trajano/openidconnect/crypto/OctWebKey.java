package net.trajano.openidconnect.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.json.JsonObjectBuilder;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class OctWebKey extends JsonWebKey {

    private String k;

    public OctWebKey() {

        setKty(KeyType.oct);
        setUse(KeyUse.enc);
    }

    public OctWebKey(SecretKey secretKey, String alg) {

        this();
        setAlg(alg);
        k = Encoding.base64urlEncode(secretKey.getEncoded());

    }

    public OctWebKey(byte[] keyBytes) {

        this();
        k = Encoding.base64urlEncode(keyBytes);
    }

    public String getK() {

        return k;
    }

    public void setK(String k) {

        this.k = k;
    }

    @Override
    public Key toJcaKey() throws GeneralSecurityException {

        return new SecretKeySpec(Encoding.base64urlDecode(k), "AES");
    }

    @Override
    protected void addToJsonObject(JsonObjectBuilder keyBuilder) {

        keyBuilder.add("k", k);

    }
}
