package net.trajano.openidconnect.jaspic.internal;

import java.util.ResourceBundle;
import java.util.logging.Logger;

import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;

/**
 * OAuth 2.0 server authentication module. This is an implementation of the <a
 * href="http://tools.ietf.org/html/rfc6749">OAuth 2.0 authentication
 * framework</a>. This assumes no HttpSessions which makes it useful for RESTful
 * applications and uses the OAuth token to manage the authentication state. The
 * e-mail addresses are not requested.
 *
 * @author Archimedes Trajano
 */
public abstract class OAuthModule implements ServerAuthModule, ServerAuthContext {

    /**
     * Access token attribute name.
     */
    public static final String ACCESS_TOKEN_KEY = "auth_access";

    /**
     * Client ID option key and JSON key.
     */
    public static final String CLIENT_ID_KEY = "client_id";

    /**
     * Client secret option key and JSON key.
     */
    public static final String CLIENT_SECRET_KEY = "client_secret";

    /**
     * Cookie context option key. The value is optional.
     */
    public static final String COOKIE_CONTEXT_KEY = "cookie_context";

    /**
     * Disable HTTP certificate checks key. This this is set to true, the auth
     * module will disable HTTPS certificate checks for the REST client
     * connections. This should only be used in development.
     */
    public static final String DISABLE_CERTIFICATE_CHECKS_KEY = "disable_certificate_checks";

    /**
     * https prefix.
     */
    protected static final String HTTPS_PREFIX = "https://";

    /**
     * Open ID token attribute name.
     */
    public static final String ID_TOKEN_KEY = "auth_idtoken";

    /**
     * Logger.
     */
    protected static final Logger LOG;

    /**
     * Logger for configuration.
     */
    protected static final Logger LOGCONFIG;

    /**
     * URI to go to when the user has logged out relative to the context path.
     */
    public static final String LOGOUT_GOTO_URI_KEY = "logout_goto_uri";

    public static final String LOGOUT_URI_KEY = "logout_uri";

    /**
     * Messages resource path.
     */
    private static final String MESSAGES = "META-INF/Messages";

    /**
     * Age cookie name. The value of this cookie is an encrypted version of the
     * IP Address and will expire based on the max age of the token.
     */
    public static final String NET_TRAJANO_AUTH_AGE = "net.trajano.auth.age";

    /**
     * ID token cookie name. This one expires when the browser closes.
     */
    public static final String NET_TRAJANO_AUTH_ID = "net.trajano.auth.id";

    /**
     * Nonce cookie name. This one expires when the browser closes.
     */
    public static final String NET_TRAJANO_AUTH_NONCE = "net.trajano.auth.nonce";

    /**
     * Resource bundle.
     */
    protected static final ResourceBundle R;

    /**
     * Redirection endpoint URI key. The value is optional and defaults to the
     * context root of the application.
     */
    public static final String REDIRECTION_ENDPOINT_URI_KEY = "redirection_endpoint"; //$NON-NLS-1$

    /**
     * Refresh token attribute name.
     */
    public static final String REFRESH_TOKEN_KEY = "auth_refresh";

    /**
     * Scope option key. The value is optional and defaults to "openid"
     */
    public static final String SCOPE_KEY = "scope";

    /**
     * Token URI key. The value is optional and if not specified, the token
     * request functionality will not be available.
     */
    public static final String TOKEN_URI_KEY = "token_uri";

    /**
     * User info attribute name.
     */
    public static final String USERINFO_KEY = "auth_userinfo";

    /**
     * User Info URI key. The value is optional and if not specified, the
     * userinfo request functionality will not be available.
     */
    public static final String USERINFO_URI_KEY = "userinfo_uri";

    static {
        LOG = Logger.getLogger("net.trajano.auth.oauthsam", MESSAGES);
        LOGCONFIG = Logger.getLogger("net.trajano.auth.oauthsam.config", MESSAGES);
        R = ResourceBundle.getBundle(MESSAGES);
    }

}
