package net.trajano.openidconnect.core;

/**
 * Registered Open ID Connect Keys. This unifies all the key string constants
 * defined in OpenID Connect specifications.
 * 
 * @author Archimedes
 */
public final class OpenIdConnectKey {

    public static final String CODE = "code";

    public static final String GRANT_TYPE = "grant_type";
    public static final String RESPONSE_TYPE="response_type";
    public static final String REDIRECT_URI = "redirect_uri";

    public static final String SCOPE = "scope";

    public static final String STATE = "state";

    public static final String CLIENT_ID = "client_id";

    private OpenIdConnectKey() {

    }
}
