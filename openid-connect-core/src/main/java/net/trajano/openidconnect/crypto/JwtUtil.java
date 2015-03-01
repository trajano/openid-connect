package net.trajano.openidconnect.crypto;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;

public class JwtUtil {

    /**
     * Logger.
     */
    private static final Logger LOG;

    static {
        LOG = Logger.getLogger("net.trajano.openidconnect");
    }

    /**
     * Gets the JWS Payload from a <a href=
     * "http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-30#section-3.1"
     * >JWS Compact Serialization</a>. The validation follows the rules in <a
     * href=
     * "http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-30#section-5.2"
     * >Message Signature or MAC validation section of JSON Web Signature</a>.
     * <p>
     * Note that "jku", "jwk", "x5u" and "x5c" should nor will <b>never</b> be
     * implemented. It does not make sense for the serialization to contain its
     * own validation.
     *
     * @param serialization
     *            JWS compact serialization
     * @param keyMap
     *            A map of key IDs to keys to obtain the key from. If this is
     *            null then signature validation will not occur.
     * @return the JWS payload
     * @throws GeneralSecurityException
     *             problem with crypto APIs or signature was not valid
     */
    public static byte[] getJwsPayload(final String serialization,
            final JsonWebKeySet jwks) throws GeneralSecurityException {

        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("serialized payload = " + serialization);
        }
        final String[] jwtParts = serialization.split("\\.");

        final JsonObject joseHeader = Json.createReader(new ByteArrayInputStream(Base64Url.decode(jwtParts[0])))
                .readObject();

        // Handle plaintext JWTs
        if (jwks == null || !"none".equals(joseHeader.getString("alg"))) {

            final String kid;
            if (joseHeader.containsKey("kid")) {
                kid = joseHeader.getString("kid");
            } else {
                kid = "";
            }

            final PublicKey signingKey = (PublicKey) jwks.getKey(kid);

            if (signingKey == null) {
                throw new GeneralSecurityException("No key with id " + kid + " defined");
            }

            final Signature signature = Signature.getInstance(JsonWebAlgorithm.valueOf(joseHeader.getString("alg"))
                    .toJca());

            final byte[] jwtSignatureBytes = Base64Url.decode(jwtParts[2]);

            signature.initVerify(signingKey);
            signature.update((jwtParts[0] + "." + jwtParts[1]).getBytes());
            if (!signature.verify(jwtSignatureBytes)) {
                throw new SignatureException("signature verification failed");
            }
        }
        return Base64Url.decode(jwtParts[1]);
    }
}
