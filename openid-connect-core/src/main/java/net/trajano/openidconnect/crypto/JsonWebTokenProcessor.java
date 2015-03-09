package net.trajano.openidconnect.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import net.trajano.openidconnect.internal.JcaJsonWebTokenCrypto;

public class JsonWebTokenProcessor {

    private String alg = JsonWebToken.ALG_NONE;

    /**
     * Flag to indicate whether jwk can be set directly.
     */
    private boolean allowJwkToBeSet = false;

    private final JsonWebTokenCrypto crypto = JcaJsonWebTokenCrypto.getInstance();

    private String enc = null;

    private JsonWebToken jsonWebToken;

    private JsonWebKey jwk = null;

    private String kid = null;

    public JsonWebTokenProcessor(final JsonWebToken jsonWebToken) {

        this.jsonWebToken = jsonWebToken;
        alg = jsonWebToken.getAlg();
        enc = jsonWebToken.getEnc();
        kid = jsonWebToken.getKid();

    }

    public JsonWebTokenProcessor(final String serialization) throws IOException {

        this(new JsonWebToken(serialization));
    }

    public JsonWebTokenProcessor allowJwkToBeSet(final boolean flag) throws IOException {

        allowJwkToBeSet = flag;
        return this;
    }

    /**
     * Gets the payload JSON object.
     *
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public JsonObject getJsonPayload() throws IOException,
    GeneralSecurityException {

        final JsonReader r = Json.createReader(new ByteArrayInputStream(getPayload()));
        return r.readObject();

    }

    public byte[] getPayload() throws IOException,
    GeneralSecurityException {

        byte[] payload;
        if (!JsonWebToken.ALG_NONE.equals(alg) && jwk == null) {
            throw new GeneralSecurityException("unable to get key");
        } else if (JsonWebToken.ALG_NONE.equals(alg)) {
            payload = jsonWebToken.getPayload(0);
        } else if (enc != null) {
            if (jsonWebToken.getNumberOfPayloads() != 4) {
                throw new GeneralSecurityException("invalid number of payloads in JWT for JWE");
            }
            payload = crypto.getJWEPayload(jsonWebToken, jwk);
        } else if (enc == null && alg != null) {
            if (jsonWebToken.getNumberOfPayloads() != 2) {
                throw new GeneralSecurityException("invalid number of payloads in JWT for JWS");
            }
            payload = crypto.getJWSPayload(jsonWebToken, jwk, alg);
        } else {
            throw new GeneralSecurityException("invalid JOSE header");
        }
        if ("DEF".equals(jsonWebToken.getZip())) {
            return crypto.inflate(payload);
        } else {
            return payload;
        }

    }

    public JsonWebTokenProcessor jwk(final JsonWebKey jwk) throws IOException {

        if (!allowJwkToBeSet) {
            throw new IOException("jwk cannot be explicitly set");
        }
        this.jwk = jwk;
        return this;

    }

    public JsonWebTokenProcessor jwks(final JsonWebKeySet jwks) throws IOException {

        if (kid != null) {
            jwk = jwks.getJwk(kid);
        }
        return this;

    }

}
