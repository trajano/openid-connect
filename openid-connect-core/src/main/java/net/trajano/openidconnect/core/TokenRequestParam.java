package net.trajano.openidconnect.core;

/**
 * <p>
 * Access Token Request.
 * </p>
 * <p>
 * The client makes a request to the token endpoint by sending the following
 * parameters using the "application/x-www-form-urlencoded" format per Appendix
 * B with a character encoding of UTF-8 in the HTTP request entity-body
 * </p>
 *
 * @see http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
 * @see http://tools.ietf.org/html/rfc6749#section-4.1.3
 */
public final class TokenRequestParam {

    /**
     * REQUIRED, if the client is not authenticating with the authorization
     * server as described in Section 3.2.1.
     */
    public static final String CLIENT_ID = "client_id";

    /**
     * REQUIRED. The authorization code received from the authorization server.
     */
    public static final String CODE = "code";

    /**
     * REQUIRED. Value MUST be set to "authorization_code".
     */
    public static final String GRANT_TYPE = "grant_type";

    /**
     * REQUIRED, if the "redirect_uri" parameter was included in the
     * authorization request as described in Section 4.1.1, and their values
     * MUST be identical.
     */
    public static final String REDIRECT_URI = "redirect_uri";

}
