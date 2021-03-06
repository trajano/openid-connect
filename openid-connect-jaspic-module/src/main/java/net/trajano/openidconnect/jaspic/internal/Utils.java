package net.trajano.openidconnect.jaspic.internal;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.json.JsonObject;
import javax.servlet.http.HttpServletRequest;

import net.trajano.openidconnect.crypto.Encoding;

/**
 * Utility methods. Normally these would be in a separate JAR file like
 * commons-lang, but to prevent complications during installation such as
 * requiring to install additional JAR files, this class was created.
 *
 * @author Archimedes Trajano
 */
public final class Utils {

    /**
     * Checks if the request uses the GET method.
     *
     * @param req
     *            request
     * @return <code>true</code> if the request uses the GET method.
     * @deprecated use {@link ValidateContext#isGetRequest()}
     */
    @Deprecated
    public static boolean isGetRequest(final HttpServletRequest req) {

        return "GET".equals(req.getMethod());
    }

    /**
     * Checks if the request uses the HEAD method.
     *
     * @param req
     *            request
     * @return <code>true</code> if the request uses the HEAD method.
     */
    public static boolean isHeadRequest(final HttpServletRequest req) {

        return "HEAD".equals(req.getMethod());
    }

    /**
     * Checks if string is null or empty.
     *
     * @param s
     *            string to test
     * @return true if string is null or empty.
     */
    public static boolean isNullOrEmpty(final String s) {

        return s == null || s.trim()
            .length() == 0;
    }

    /**
     * Checks if the request is to retrieve data (i.e. "GET" or "HEAD" method).
     *
     * @param req
     *            request
     * @return <code>true</code> if the request uses the GET or HEAD method.
     */
    public static boolean isRetrievalRequest(final HttpServletRequest req) {

        return isGetRequest(req) || isHeadRequest(req);
    }

    /**
     * Validates the ID Token.
     *
     * @param clientId
     *            client ID
     * @param idTokenJson
     *            ID Token JSON.
     * @throws GeneralSecurityException
     */
    public static void validateIdToken(final String clientId,
        final JsonObject idTokenJson,
        final String nonce,
        final String accessToken) throws GeneralSecurityException {

        // TODO handle multiple audiences
        if (!clientId.equals(idTokenJson.getString("aud"))) {
            throw new GeneralSecurityException(String.format("invalid 'aud' got' %s' expected '%s'", idTokenJson.getString("aud"), clientId));
        }
        if (nonce != null && !nonce.equals(idTokenJson.getString("nonce"))) {
            throw new GeneralSecurityException(String.format("invalid 'nonce' got' %s' expected '%s'", idTokenJson.getString("nonce"), clientId));
        }
        if (idTokenJson.containsKey("azp") && !clientId.equals(idTokenJson.getString("azp"))) {
            throw new GeneralSecurityException(String.format("invalid 'azp' got' %s' expected '%s'", idTokenJson.getString("azp"), clientId));
        }
        if (idTokenJson.containsKey("exp")) {
            final long delta = System.currentTimeMillis() - idTokenJson.getInt("exp") * 1000L;
            if (delta >= 0) {
                throw new GeneralSecurityException("expired " + delta + "ms ago");
            }
        }
        if (idTokenJson.containsKey("at_hash")) {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] digestedBytes = digest.digest(accessToken.getBytes());
            if (!Encoding.base64urlEncode(digestedBytes, 0, 128 / 8)
                .equals(idTokenJson.getString("at_hash"))) {
                throw new GeneralSecurityException("access token hash mismatch");
            }
        }
    }

    /**
     * Prevent instantiation of utility class.
     */
    private Utils() {

    }
}
