package net.trajano.openidconnect.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import net.trajano.openidconnect.internal.JcaJsonWebTokenCrypto;

public class JsonWebTokenProcessor {

    private final JsonWebTokenCrypto crypto = JcaJsonWebTokenCrypto.getInstance();

    private JsonWebKey jwk = null;

    private JsonWebToken jsonWebToken;

    private String alg = JsonWebToken.ALG_NONE;

    private String enc = null;

    private String kid = null;

    public JsonWebTokenProcessor(String serialization) throws IOException {

        this(new JsonWebToken(serialization));
    }

    public JsonWebTokenProcessor(JsonWebToken jsonWebToken) {

        this.jsonWebToken = jsonWebToken;
        alg = jsonWebToken.getAlg();
        enc = jsonWebToken.getEnc();
        kid = jsonWebToken.getKid();

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

    public JsonWebTokenProcessor jwks(JsonWebKeySet jwks) throws IOException {

        if (kid != null) {
            jwk = jwks.getJwk(kid);
        }
        return this;

    }

    public JsonWebTokenProcessor jwk(JsonWebKey jwk) throws IOException {

        this.jwk = jwk;
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

        JsonReader r = Json.createReader(new ByteArrayInputStream(getPayload()));
        return r.readObject();

    }

}
