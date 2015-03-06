package net.trajano.openidconnect.core;

/**
 * Registered Open ID Connect Keys. This unifies all the key string constants
 * defined in OpenID Connect specifications.
 *
 * @author Archimedes
 */
public final class OpenIdConnectKey {

    public static final String CLIENT_ID = "client_id";

    public static final String CLIENT_SECRET = "client_secret";

    public static final String CODE = "code";

    public static final String GRANT_TYPE = "grant_type";

    public static final String REDIRECT_URI = "redirect_uri";

    public static final String RESPONSE_TYPE = "response_type";

    public static final String SCOPE = "scope";

    /**
     * REQUIRED. Error code.
     */
    public static final String ERROR = "error";

    /**
     * OPTIONAL. Human-readable ASCII encoded text description of the error.
     */
    public static final String ERROR_DESCRIPTION = "error_description";

    /**
     * OPTIONAL. URI of a web page that includes additional information about
     * the error.
     */
    public static final String ERROR_URI = "error_uri";

    /**
     * OAuth 2.0 state value. REQUIRED if the Authorization Request included the
     * state parameter. Set to the value received from the Client.
     */
    public static final String STATE = "state";

    private OpenIdConnectKey() {

    }
}
