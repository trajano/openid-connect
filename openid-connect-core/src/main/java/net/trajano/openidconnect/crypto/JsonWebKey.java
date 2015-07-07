package net.trajano.openidconnect.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;

import javax.json.JsonObjectBuilder;
import javax.validation.constraints.NotNull;

public abstract class JsonWebKey {

    private String alg;

    private String kid;

    private KeyType kty;

    private KeyUse use;

    public String getAlg() {

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

    public void setAlg(final String alg) {

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
     * @return JCA key.
     */
    public abstract Key toJcaKey() throws GeneralSecurityException;

    /**
     * Converts the JSON Web key to the JCA Public key. This may be overriden by
     * keys that can derive their own public key from their private key.
     * 
     * @return JCA public key.
     */
    public PublicKey toJcaPublicKey() throws GeneralSecurityException {

        return null;
    }

    /**
     * Builds the JSON object.
     * 
     * @param keyBuilder builder
     */
    public void buildJsonObject(@NotNull final JsonObjectBuilder keyBuilder) {

        keyBuilder.add("kid", kid);
        keyBuilder.add("alg", alg.toString());
        keyBuilder.add("kty", kty.toString());
        keyBuilder.add("use", use.toString());
        addToJsonObject(keyBuilder);
    }

    /**
     * adds additional data to the json object.
     * 
     * @param keyBuilder builder
     */
    protected abstract void addToJsonObject(JsonObjectBuilder keyBuilder);
}
