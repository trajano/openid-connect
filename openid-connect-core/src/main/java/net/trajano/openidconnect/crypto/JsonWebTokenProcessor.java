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

    /**
     * Flag to indicate that signature check is required.
     */
    private boolean signatureCheck = true;

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
        if (JsonWebToken.ALG_NONE.equals(alg)) {
            payload = jsonWebToken.getPayload(0);
        } else if (enc != null) {
            if (jsonWebToken.getNumberOfPayloads() != 4) {
                throw new GeneralSecurityException("invalid number of payloads in JWT for JWE");
            }
            payload = crypto.getJWEPayload(jsonWebToken, jwk);
        } else if (enc == null && alg != null && signatureCheck) {
            if (jsonWebToken.getNumberOfPayloads() != 2) {
                throw new GeneralSecurityException("invalid number of payloads in JWT for JWS");
            }
            if (jwk == null) {
                throw new GeneralSecurityException("No JWK available to validate signature");
            }
            payload = crypto.getJWSPayload(jsonWebToken, jwk, alg);
        } else if (enc == null && alg != null && !signatureCheck) {
            if (jsonWebToken.getNumberOfPayloads() != 2) {
                throw new GeneralSecurityException("invalid number of payloads in JWT for JWS");
            }
            payload = jsonWebToken.getPayload(0);
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
        } else if (jwks.getKeys().length == 1) {
            jwk = jwks.getKeys()[0];
        }
        return this;

    }

    /**
     * Checks if the JWK is already set for the processor. The value is not set
     * if the {@link #jwk(JsonWebKey)} is not called or the
     * {@link #jwks(JsonWebKeySet)} is not called or does not contain the key
     * specified by the {@link #kid}.
     * 
     * @return jwk is set.
     */
    public boolean isJwkAvailable() {

        return jwk != null;
    }

    /**
     * Enable or disable signature checks. Signature checks are enabled by
     * default. Signature checks can be disabled for scenarios where the
     * signature had already been validated previously in the process and the
     * JWT was stored as is rather than having the extracted payload kept.
     */
    public JsonWebTokenProcessor signatureCheck(boolean b) {

        signatureCheck = b;
        return this;

    }

}
