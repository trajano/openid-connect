package net.trajano.openidconnect.crypto;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

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
            final JsonWebKeySet jwks) throws IOException,
            GeneralSecurityException {

        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("serialized payload = " + serialization);
        }

        JsonWebTokenProcessor p = new JsonWebTokenProcessor(serialization);
        p.jwks(jwks);
        return p.getPayload();
    }
}
