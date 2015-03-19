package net.trajano.openidconnect.jaspic;

import static net.trajano.openidconnect.core.OpenIdConnectKey.CLIENT_ID;
import static net.trajano.openidconnect.core.OpenIdConnectKey.CLIENT_SECRET;
import static net.trajano.openidconnect.core.OpenIdConnectKey.CODE;
import static net.trajano.openidconnect.core.OpenIdConnectKey.GRANT_TYPE;
import static net.trajano.openidconnect.core.OpenIdConnectKey.REDIRECT_URI;
import static net.trajano.openidconnect.core.OpenIdConnectKey.RESPONSE_MODE;
import static net.trajano.openidconnect.core.OpenIdConnectKey.SCOPE;
import static net.trajano.openidconnect.jaspic.internal.Utils.isHeadRequest;
import static net.trajano.openidconnect.jaspic.internal.Utils.isNullOrEmpty;
import static net.trajano.openidconnect.jaspic.internal.Utils.isRetrievalRequest;
import static net.trajano.openidconnect.jaspic.internal.Utils.validateIdToken;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.Map;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.json.JsonObject;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.auth.ResponseMode;
import net.trajano.openidconnect.auth.ResponseType;
import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.core.OpenIdProviderConfiguration;
import net.trajano.openidconnect.crypto.Encoding;
import net.trajano.openidconnect.crypto.JsonWebTokenBuilder;
import net.trajano.openidconnect.crypto.JsonWebTokenProcessor;
import net.trajano.openidconnect.jaspic.internal.CipherUtil;
import net.trajano.openidconnect.jaspic.internal.Log;
import net.trajano.openidconnect.jaspic.internal.NullHostnameVerifier;
import net.trajano.openidconnect.jaspic.internal.NullX509TrustManager;
import net.trajano.openidconnect.jaspic.internal.TokenCookie;
import net.trajano.openidconnect.jaspic.internal.ValidateContext;
import net.trajano.openidconnect.jaspic.internal.ValidateRequestProcessor;
import net.trajano.openidconnect.jaspic.internal.ValidateRequestProcessors;
import net.trajano.openidconnect.rs.JsonWebKeyProvider;
import net.trajano.openidconnect.rs.JsonWebKeySetProvider;
import net.trajano.openidconnect.token.GrantType;
import net.trajano.openidconnect.token.IdTokenResponse;

/**
 * OpenID Connect Server Auth Module. This uses OpenID Connect Discovery to
 * configure the OAuth 2.0 Login.
 * <p>
 * OAuth 2.0 server authentication module. This is an implementation of the <a
 * href="http://tools.ietf.org/html/rfc6749">OAuth 2.0 authentication
 * framework</a>. This assumes no HttpSessions which makes it useful for RESTful
 * applications and uses the OAuth token to manage the authentication state. The
 * e-mail addresses are not requested.
 * </p>
 *
 * @author Archimedes Trajano
 */
public class OpenIdConnectAuthModule implements ServerAuthModule, ServerAuthContext {

    /**
     * Access token attribute name.
     */
    public static final String ACCESS_TOKEN_KEY = "auth_access";

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
     * Issuer URI option key.
     */
    public static final String ISSUER_URI_KEY = "issuer_uri";

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
     * Age cookie name. The value of this cookie is an encrypted version of the
     * IP Address and will expire based on the max age of the token.
     */
    public static final String NET_TRAJANO_AUTH_AGE = "net.trajano.oidc.age";

    /**
     * ID token cookie name. This one expires when the browser closes.
     */
    public static final String NET_TRAJANO_AUTH_ID = "net.trajano.oidc.id";

    /**
     * Nonce cookie name. This one expires when the browser closes.
     */
    public static final String NET_TRAJANO_AUTH_NONCE = "net.trajano.oidc.nonce";

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
        LOGCONFIG = Logger.getLogger("net.trajano.oidc.jaspic.config", "META-INF/Messages");
    }

    /**
     * Client ID. This is set through {@value #CLIENT_ID_KEY} option.
     */
    private String clientId;

    /**
     * Client secret. This is set through {@value #CLIENT_SECRET_KEY} option.
     */
    private String clientSecret;

    /**
     * Cookie context path. Set through through "cookie_context" option. This is
     * optional.
     */
    private String cookieContext;

    /**
     * Callback handler.
     */
    private CallbackHandler handler;

    /**
     * Flag to indicate that authentication is mandatory.
     */
    private boolean mandatory;

    /**
     * Options for the module.
     */
    private Map<String, String> moduleOptions;

    /**
     * Randomizer.
     */
    private final Random random = new SecureRandom();

    /**
     * Redirection endpoint URI. This is set through "redirection_endpoint"
     * option. This must start with a forward slash. This value is optional.
     */
    private String redirectionEndpointUri;

    /**
     * Response mode used by the module.
     */
    private ResponseMode responseMode = ResponseMode.query;

    /**
     * REST Client. This is not final so a different one can be put in for
     * testing.
     */
    private Client restClient;

    /**
     * Scope.
     */
    private String scope;

    /**
     * Secret key used for module level ciphers.
     */
    private SecretKey secret;

    /**
     * Token URI. This is set through "token_uri" option. This must start with a
     * forward slash. This value is optional. The calling the token URI will
     * return the contents of the JWT token object to the user. Make sure that
     * this is intended before setting the value.
     */
    private String tokenUri;

    /**
     * User info URI. This is set through "userinfo_uri" option. This must start
     * with a forward slash. This value is optional. The calling the user info
     * URI will return the contents of the user info object to the user. Make
     * sure that this is intended before setting the value.
     */
    private String userInfoUri;

    /**
     * Builds a REST client that bypasses SSL security checks. Made public so it
     * can be used for testing.
     *
     * @return JAX-RS client.
     */
    public Client buildUnsecureRestClient() throws GeneralSecurityException {

        final SSLContext context = SSLContext.getInstance("TLSv1");
        final TrustManager[] trustManagerArray = { NullX509TrustManager.INSTANCE };
        context.init(null, trustManagerArray, null);
        return ClientBuilder.newBuilder()
                .hostnameVerifier(NullHostnameVerifier.INSTANCE)
                .sslContext(context)
                .build();
    }

    /**
     * Does nothing.
     *
     * @param messageInfo
     *            message info
     * @param subject
     *            subject
     */
    @Override
    public void cleanSubject(final MessageInfo messageInfo,
            final Subject subject) throws AuthException {

        // subject.getPrincipals().
        // Does nothing.
    }

    private void deleteAuthCookies(final HttpServletResponse resp) {

        for (final String cookieName : new String[] { NET_TRAJANO_AUTH_ID, NET_TRAJANO_AUTH_AGE  }) {
            final Cookie deleteCookie = new Cookie(cookieName, "");
            deleteCookie.setMaxAge(0);
            deleteCookie.setPath(cookieContext);
            resp.addCookie(deleteCookie);
        }
    }

    /**
     * Client ID.
     *
     * @return the client ID.
     */
    protected String getClientId() {

        return clientId;
    }

    /**
     * Client Secret.
     *
     * @return the client secret.
     */
    protected String getClientSecret() {

        return clientSecret;
    }

    /**
     * Gets the ID token. This ensures that both cookies are present, if not
     * then this will return <code>null</code>.
     *
     * @param req
     *            HTTP servlet request
     * @return ID token
     * @throws GeneralSecurityException
     * @throws IOException
     */
    private String getIdToken(final HttpServletRequest req) throws GeneralSecurityException,
            IOException {

        final Cookie[] cookies = req.getCookies();
        if (cookies == null) {
            return null;
        }
        String idToken = null;
        boolean foundAge = false;
        for (final Cookie cookie : cookies) {
            if (NET_TRAJANO_AUTH_ID.equals(cookie.getName()) && !isNullOrEmpty(cookie.getValue())) {
                idToken = cookie.getValue();
            } else if (NET_TRAJANO_AUTH_AGE.equals(cookie.getName())) {
                final String remoteAddr = req.getRemoteAddr();
                final String cookieAddr = new String(CipherUtil.decrypt(Encoding.base64urlDecode(cookie.getValue()), secret), "US-ASCII");
                if (!remoteAddr.equals(cookieAddr)) {
                    throw new AuthException(MessageFormat.format(Log.r("ipaddressMismatch"), remoteAddr, cookieAddr));
                }
                foundAge = true;
            }
            if (idToken != null && foundAge) {
                return idToken;
            }
        }
        return null;
    }

    /**
     * Lets subclasses change the provider configuration.
     *
     * @param req
     *            request message
     * @param client
     *            REST client
     * @param options
     *            module options
     * @return configuration
     * @throws AuthException
     *             wraps exceptions thrown during processing
     */
    protected OpenIdProviderConfiguration getOpenIDProviderConfig(final HttpServletRequest req,
            final Client restClient,
            final Map<String, String> options) throws AuthException {

        final String issuerUri = options.get(ISSUER_URI_KEY);
        if (issuerUri == null) {
            Log.severe("missingOption", ISSUER_URI_KEY);
            throw new AuthException(MessageFormat.format(Log.r("missingOption"), ISSUER_URI_KEY));
        }
        return restClient.target(URI.create(issuerUri)
                .resolve("/.well-known/openid-configuration"))
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(OpenIdProviderConfiguration.class);
    }

    /**
     * This gets the redirection endpoint URI. It uses the
     * {@link #REDIRECTION_ENDPOINT_URI_KEY} option resolved against the request
     * URL to get the host name.
     *
     * @param req
     *            request
     * @return redirection endpoint URI.
     */
    protected URI getRedirectionEndpointUri(final HttpServletRequest req) {

        return URI.create(req.getRequestURL()
                .toString())
                .resolve(redirectionEndpointUri);
    }

    /**
     * Gets an option and ensures it is present.
     *
     * @param optionKey
     *            option key
     * @return the option value
     * @throws AuthException
     *             missing option exception
     */
    private String getRequiredOption(final String optionKey) throws AuthException {

        final String optionValue = moduleOptions.get(optionKey);
        if (optionValue == null) {
            Log.severe("missingOption", optionKey);
            throw new AuthException(MessageFormat.format(Log.r("missingOption"), optionKey));
        }
        return optionValue;
    }

    /**
     * REST client.
     *
     * @return REST client
     */
    protected Client getRestClient() {

        return restClient;
    }

    private String getState(final HttpServletRequest req) {

        final StringBuilder stateBuilder = new StringBuilder(req.getRequestURI()
                .substring(req.getContextPath()
                        .length()));
        if (req.getQueryString() != null) {
            stateBuilder.append('?');
            stateBuilder.append(req.getQueryString());
        }
        return Encoding.base64UrlEncode(stateBuilder.toString());
    }

    /**
     * <p>
     * Supported message types. For our case we only need to deal with HTTP
     * servlet request and responses. On Java EE 7 this will handle WebSockets
     * as well.
     * </p>
     * <p>
     * This creates a new array for security at the expense of performance.
     * </p>
     *
     * @return {@link HttpServletRequest} and {@link HttpServletResponse}
     *         classes.
     */
    @SuppressWarnings("rawtypes")
    @Override
    public Class[] getSupportedMessageTypes() {

        return new Class<?>[] { HttpServletRequest.class, HttpServletResponse.class };
    }

    /**
     * Sends a request to the token endpoint to get the token for the code.
     *
     * @param req
     *            servlet request
     * @param oidProviderConfig
     *            OpenID provider config
     * @return token response
     */
    protected IdTokenResponse getToken(final HttpServletRequest req,
            final OpenIdProviderConfiguration oidProviderConfig) throws IOException {

        final MultivaluedMap<String, String> requestData = new MultivaluedHashMap<>();
        requestData.putSingle(CODE, req.getParameter("code"));
        requestData.putSingle(GRANT_TYPE, "authorization_code");
        requestData.putSingle(REDIRECT_URI, getRedirectionEndpointUri(req).toASCIIString());

        try {
            final String authorization = "Basic " + Encoding.base64Encode(clientId + ":" + clientSecret);
            final IdTokenResponse authorizationTokenResponse = restClient.target(oidProviderConfig.getTokenEndpoint())
                    .request(MediaType.APPLICATION_JSON_TYPE)
                    .header("Authorization", authorization)
                    .post(Entity.form(requestData), IdTokenResponse.class);
            if (Log.isFinestLoggable()) {
                Log.getInstance()
                        .finest("authorization token response =  " + authorizationTokenResponse);
            }
            return authorizationTokenResponse;
        } catch (final BadRequestException e) {
            // workaround for google that does not support BASIC authentication
            // on their endpoint.
            requestData.putSingle(CLIENT_ID, clientId);
            requestData.putSingle(CLIENT_SECRET, clientSecret);
            final IdTokenResponse authorizationTokenResponse = restClient.target(oidProviderConfig.getTokenEndpoint())
                    .request(MediaType.APPLICATION_JSON_TYPE)
                    .post(Entity.form(requestData), IdTokenResponse.class);
            if (Log.isFinestLoggable()) {
                Log.getInstance()
                        .finest("authorization token response =  " + authorizationTokenResponse);
            }
            return authorizationTokenResponse;
        }
    }

    /**
     * Sends a request to the token endpoint to get the token for the code.
     *
     * @param req
     *            servlet request
     * @param oidProviderConfig
     *            OpenID provider config
     * @return token response
     */
    protected IdTokenResponse getTokenViaRefresh(final HttpServletRequest req,
            final String refreshToken,
            final OpenIdProviderConfiguration oidProviderConfig) throws IOException {

        final MultivaluedMap<String, String> requestData = new MultivaluedHashMap<>();
        requestData.putSingle(OpenIdConnectKey.REFRESH_TOKEN, refreshToken);
        requestData.putSingle(GRANT_TYPE, GrantType.refresh_token.name());
        requestData.putSingle(REDIRECT_URI, getRedirectionEndpointUri(req).toASCIIString());

        try {
            final String authorization = "Basic " + Encoding.base64Encode(clientId + ":" + clientSecret);
            final IdTokenResponse authorizationTokenResponse = restClient.target(oidProviderConfig.getTokenEndpoint())
                    .request(MediaType.APPLICATION_JSON_TYPE)
                    .header("Authorization", authorization)
                    .post(Entity.form(requestData), IdTokenResponse.class);
            if (Log.isFinestLoggable()) {
                Log.getInstance()
                        .finest("authorization token response =  " + authorizationTokenResponse);
            }
            return authorizationTokenResponse;
        } catch (final BadRequestException e) {
            // workaround for google that does not support BASIC authentication
            // on their endpoint.
            requestData.putSingle(CLIENT_ID, clientId);
            requestData.putSingle(CLIENT_SECRET, clientSecret);
            final IdTokenResponse authorizationTokenResponse = restClient.target(oidProviderConfig.getTokenEndpoint())
                    .request(MediaType.APPLICATION_JSON_TYPE)
                    .post(Entity.form(requestData), IdTokenResponse.class);
            if (Log.isFinestLoggable()) {
                Log.getInstance()
                        .finest("authorization token response =  " + authorizationTokenResponse);
            }
            return authorizationTokenResponse;
        }
    }

    /**
     * Gets the web keys from the options and the OpenID provider configuration.
     * This may be overridden by clients.
     *
     * @param config
     *            provider configuration
     * @return web keys
     * @throws GeneralSecurityException
     *             wraps exceptions thrown during processing
     */
    private net.trajano.openidconnect.crypto.JsonWebKeySet getWebKeys(final OpenIdProviderConfiguration config) throws GeneralSecurityException {

        return restClient.target(config.getJwksUri())
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(net.trajano.openidconnect.crypto.JsonWebKeySet.class);
    }

    /**
     * Workaround for the issuer value for Google. This was documented in
     * 15.6.2. of the spec. In which case if the issuer does not start with
     * https:// it will prepend it.
     *
     * @param issuer
     *            issuer
     * @return updated issuer
     */
    private String googleWorkaround(final String issuer) {

        if (issuer.startsWith(HTTPS_PREFIX)) {
            return issuer;
        }
        return HTTPS_PREFIX + issuer;
    }

    /**
     * {@inheritDoc}
     *
     * @param requestPolicy
     *            request policy, ignored
     * @param responsePolicy
     *            response policy, ignored
     * @param h
     *            callback handler
     * @param options
     *            options
     */
    @SuppressWarnings("unchecked")
    @Override
    public void initialize(final MessagePolicy requestPolicy,
            final MessagePolicy responsePolicy,
            final CallbackHandler h,
            @SuppressWarnings("rawtypes") final Map options) throws AuthException {

        try {
            moduleOptions = options;
            clientId = getRequiredOption(CLIENT_ID);
            cookieContext = moduleOptions.get(COOKIE_CONTEXT_KEY);
            redirectionEndpointUri = getRequiredOption(REDIRECTION_ENDPOINT_URI_KEY);
            tokenUri = moduleOptions.get(TOKEN_URI_KEY);
            userInfoUri = moduleOptions.get(USERINFO_URI_KEY);
            scope = moduleOptions.get(SCOPE);
            if (isNullOrEmpty(scope)) {
                scope = "openid";
            }
            clientSecret = getRequiredOption(CLIENT_SECRET);
            LOGCONFIG.log(Level.CONFIG, "options", moduleOptions);

            final String responseModeIn = moduleOptions.get(OpenIdConnectKey.RESPONSE_MODE);
            if (responseModeIn != null) {
                responseMode = ResponseMode.valueOf(responseModeIn);
            }
            handler = h;
            mandatory = requestPolicy.isMandatory();
            secret = CipherUtil.buildSecretKey(clientId, clientSecret);

            if (restClient == null) {
                if (moduleOptions.get(DISABLE_CERTIFICATE_CHECKS_KEY) != null && Boolean.valueOf(moduleOptions.get(DISABLE_CERTIFICATE_CHECKS_KEY))) {
                    restClient = buildUnsecureRestClient();
                } else {
                    restClient = ClientBuilder.newClient();
                }
                restClient.register(JsonWebKeySetProvider.class)
                        .register(JsonWebKeyProvider.class);

            }
        } catch (final Exception e) {
            // Should not happen
            Log.severe("initializeException", e);
            throw new AuthException(MessageFormat.format(Log.r("initializeException"), e.getMessage()));
        }
    }

    /**
     * Generate the next nonce.
     *
     * @return nonce
     */
    private String nextNonce() {

        final byte[] bytes = new byte[8];
        random.nextBytes(bytes);
        return Encoding.base64urlEncode(bytes);
    }

    /**
     * Builds the token cookie and updates the subject principal and sets the
     * token and user info attribute in the request. Any exceptions or
     * validation problems during validation will make this return
     * <code>null</code> to indicate that there was no valid token.
     *
     * @param subject
     *            subject
     * @param req
     *            servlet request
     * @return token cookie.
     */
    private TokenCookie processTokenCookie(final Subject subject,
            final HttpServletRequest req,
            final HttpServletResponse resp) {

        try {
            final String idToken = getIdToken(req);
            TokenCookie tokenCookie = null;
            if (idToken != null) {
                tokenCookie = new TokenCookie(idToken, secret);
                if (tokenCookie.isExpired() && tokenCookie.getRefreshToken() != null) {
                    final OpenIdProviderConfiguration oidProviderConfig = getOpenIDProviderConfig(req, restClient, moduleOptions);
                    final IdTokenResponse token = getTokenViaRefresh(req, tokenCookie.getRefreshToken(), oidProviderConfig);
                    final net.trajano.openidconnect.crypto.JsonWebKeySet webKeys = getWebKeys(oidProviderConfig);

                    final JsonObject claimsSet = new JsonWebTokenProcessor(token.getEncodedIdToken()).jwks(webKeys)
                            .getJsonPayload();

                    final String iss = googleWorkaround(claimsSet.getString("iss"));
                    final String issuer = googleWorkaround(oidProviderConfig.getIssuer());
                    if (!iss.equals(issuer)) {
                        Log.severe("issuerMismatch", iss, issuer);
                        throw new GeneralSecurityException(Log.r("issuerMismatch", iss, issuer));
                    }
                    updateSubjectPrincipal(subject, claimsSet);

                    if (oidProviderConfig.getUserinfoEndpoint() != null && Pattern.compile("\\bprofile\\b")
                            .matcher(scope)
                            .find()) {
                        final Response userInfoResponse = restClient.target(oidProviderConfig.getUserinfoEndpoint())
                                .request(MediaType.APPLICATION_JSON_TYPE)
                                .header("Authorization", token.getTokenType() + " " + token.getAccessToken())
                                .get();
                        if (userInfoResponse.getStatus() == 200) {
                            tokenCookie = new TokenCookie(token.getAccessToken(), token.getRefreshToken(), claimsSet, token.getEncodedIdToken(), userInfoResponse.readEntity(JsonObject.class));
                        } else {
                            Log.getInstance()
                                    .log(Level.WARNING, "unableToGetProfile");
                            tokenCookie = new TokenCookie(claimsSet, token.getEncodedIdToken());
                        }
                    } else {
                        tokenCookie = new TokenCookie(claimsSet, token.getEncodedIdToken());
                    }

                    final String requestCookieContext;
                    if (isNullOrEmpty(cookieContext)) {
                        requestCookieContext = req.getContextPath();
                    } else {
                        requestCookieContext = cookieContext;
                    }

                    final Cookie idTokenCookie = new Cookie(NET_TRAJANO_AUTH_ID, tokenCookie.toCookieValue(secret));
                    idTokenCookie.setMaxAge(-1);
                    idTokenCookie.setSecure(true);
                    idTokenCookie.setHttpOnly(true);
                    idTokenCookie.setPath(requestCookieContext);
                    resp.addCookie(idTokenCookie);

                }
                validateIdToken(clientId, tokenCookie.getIdToken(), null, tokenCookie.getAccessToken());
                updateSubjectPrincipal(subject, tokenCookie.getIdToken());

                req.setAttribute(ACCESS_TOKEN_KEY, tokenCookie.getAccessToken());
                req.setAttribute(REFRESH_TOKEN_KEY, tokenCookie.getRefreshToken());
                req.setAttribute(ID_TOKEN_KEY, tokenCookie.getIdToken());
                if (tokenCookie.getUserInfo() != null) {
                    req.setAttribute(USERINFO_KEY, tokenCookie.getUserInfo());
                }
            }
            return tokenCookie;
        } catch (final GeneralSecurityException | IOException e) {
            e.printStackTrace();
            Log.getInstance()
                    .log(Level.FINE, "invalidToken", e.getMessage());
            Log.getInstance()
                    .throwing(this.getClass()
                            .getName(), "validateRequest", e);
            return null;
        }
    }

    /**
     * Sends a redirect to the authorization endpoint. It sends the current
     * request URI as the state so that the user can be redirected back to the
     * last place. However, this does not work for non-idempotent requests such
     * as POST in those cases it will result in a 401 error and
     * {@link AuthStatus#SEND_FAILURE}. For idempotent requests, it will build
     * the redirect URI and return {@link AuthStatus#SEND_CONTINUE}. It will
     * also destroy the cookies used for authorization as part of the response.
     * <p>
     * It stores an encrypted nonce in the cookies and uses it to verify the
     * nonce value later.
     * </p>
     *
     * @param req
     *            HTTP servlet request
     * @param resp
     *            HTTP servlet response
     * @param reason
     *            reason for redirect (used for logging)
     * @return authentication status
     * @throws AuthException
     */
    private AuthStatus redirectToAuthorizationEndpoint(final HttpServletRequest req,
            final HttpServletResponse resp,
            final String reason) throws AuthException {

        Log.fine("redirecting", reason);
        URI authorizationEndpointUri = null;
        try {
            final OpenIdProviderConfiguration oidProviderConfig = getOpenIDProviderConfig(req, restClient, moduleOptions);

            final String state = getState(req);

            final String requestCookieContext;
            if (isNullOrEmpty(cookieContext)) {
                requestCookieContext = req.getContextPath();
            } else {
                requestCookieContext = cookieContext;
            }

            final String nonce = nextNonce();
            final Cookie nonceCookie = new Cookie(NET_TRAJANO_AUTH_NONCE, Encoding.base64urlEncode(CipherUtil.encrypt(nonce.getBytes(), secret)));
            nonceCookie.setMaxAge(-1);
            nonceCookie.setPath(requestCookieContext);
            nonceCookie.setHttpOnly(true);
            nonceCookie.setSecure(true);
            resp.addCookie(nonceCookie);

            final URI redirectUri = URI.create(req.getRequestURL()
                    .toString())
                    .resolve(moduleOptions.get(REDIRECTION_ENDPOINT_URI_KEY));

            final AuthenticationRequest ab = new AuthenticationRequest.Builder().clientId(clientId)
                    .scope(scope)
                    .redirectUri(redirectUri)
                    .responseType(ResponseType.code)
                    .state(state)
                    .nonce(nonce)
                    .uiLocale(req.getLocales())
                    .responseMode(responseMode)
                    .build();

            final UriBuilder b = UriBuilder.fromUri(oidProviderConfig.getAuthorizationEndpoint());
            if (oidProviderConfig.isRequestParameterSupported()) {

                // TODO compare with own list.
                final JsonWebTokenBuilder jwtBuilder = new JsonWebTokenBuilder().alg(oidProviderConfig.getRequestObjectEncryptionAlgValuesSupported()
                        .get(0))
                        .enc(oidProviderConfig.getRequestObjectEncryptionEncValuesSupported()
                                .get(0))
                        .compress(true)
                        .jwk(getWebKeys(oidProviderConfig))
                        .payload(ab.toJsonObject());
                b.queryParam(OpenIdConnectKey.REQUEST, jwtBuilder.build()
                        .toString());

            } else {
                ab.addQueryParams(b);

                if (responseMode != ResponseMode.query) {
                    b.queryParam(RESPONSE_MODE, responseMode.toString());
                }
            }
            authorizationEndpointUri = b.build();
            deleteAuthCookies(resp);

            resp.sendRedirect(authorizationEndpointUri.toASCIIString());
            return AuthStatus.SEND_CONTINUE;
        } catch (final IOException | GeneralSecurityException e) {
            // Should not happen
            Log.getInstance()
                    .log(Level.SEVERE, "sendRedirectException", new Object[] { authorizationEndpointUri, e.getMessage() });
            Log.getInstance()
                    .throwing(this.getClass()
                            .getName(), "redirectToAuthorizationEndpoint", e);
            throw new AuthException(MessageFormat.format(Log.r("sendRedirectException"), authorizationEndpointUri, e.getMessage()));
        }
    }

    /**
     * Return {@link AuthStatus#SEND_SUCCESS}.
     *
     * @param messageInfo
     *            contains the request and response messages. At this point the
     *            response message is already committed so nothing can be
     *            changed.
     * @param subject
     *            subject.
     * @return {@link AuthStatus#SEND_SUCCESS}
     */
    @Override
    public AuthStatus secureResponse(final MessageInfo messageInfo,
            final Subject subject) throws AuthException {

        return AuthStatus.SEND_SUCCESS;
    }

    /**
     * Override REST client for testing.
     *
     * @param restClient
     *            REST client. May be mocked.
     */
    public void setRestClient(final Client restClient) {

        this.restClient = restClient;
    }

    /**
     * Updates the principal for the subject. This is done through the
     * callbacks.
     *
     * @param subject
     *            subject
     * @param jwtPayload
     *            JWT payload
     * @throws AuthException
     * @throws GeneralSecurityException
     */
    private void updateSubjectPrincipal(final Subject subject,
            final JsonObject jwtPayload) throws GeneralSecurityException {

        try {
            final String iss = googleWorkaround(jwtPayload.getString("iss"));
            handler.handle(new Callback[] { new CallerPrincipalCallback(subject, UriBuilder.fromUri(iss)
                    .userInfo(jwtPayload.getString("sub"))
                    .build()
                    .toASCIIString()), new GroupPrincipalCallback(subject, new String[] { iss }) });
        } catch (final IOException | UnsupportedCallbackException e) {
            // Should not happen
            Log.getInstance()
                    .log(Level.SEVERE, "updatePrincipalException", e.getMessage());
            Log.getInstance()
                    .throwing(this.getClass()
                            .getName(), "updateSubjectPrincipal", e);
            throw new AuthException(MessageFormat.format(Log.r("updatePrincipalException"), e.getMessage()));
        }
    }

    /**
     * Validates the request. The request must be secure otherwise it will
     * return {@link AuthStatus#FAILURE}. It then tries to build the token
     * cookie data if available, if the token is valid, subject is set correctly
     * and user info data if present is stored in the request, then call HTTP
     * method specific operations.
     *
     * @param messageInfo
     *            request and response
     * @param clientSubject
     *            client subject
     * @param serviceSubject
     *            service subject, ignored.
     * @return Auth status
     */
    @Override
    public AuthStatus validateRequest(final MessageInfo messageInfo,
            final Subject clientSubject,
            final Subject serviceSubject) throws AuthException {

        final HttpServletRequest req = (HttpServletRequest) messageInfo.getRequestMessage();
        final HttpServletResponse resp = (HttpServletResponse) messageInfo.getResponseMessage();

        try {
            final TokenCookie tokenCookie = processTokenCookie(clientSubject, req, resp);

            final ValidateContext context = new ValidateContext(restClient, clientSubject, mandatory, moduleOptions, req, resp, tokenCookie, cookieContext, handler);

            final ValidateRequestProcessor requestProcessor = ValidateRequestProcessors.getInstance();

            final AuthStatus status = requestProcessor.validateRequest(context);
            if (status != null) {
                return status;
            }

            if (mandatory && tokenCookie != null && tokenCookie.isExpired()) {
                return redirectToAuthorizationEndpoint(req, resp, "token cookie is expired");
            }

            if (mandatory && tokenCookie == null) {
                return redirectToAuthorizationEndpoint(req, resp, "token cookie is missing");
            }

            if (req.isSecure() && isHeadRequest(req) && req.getRequestURI()
                    .equals(tokenUri)) {
                resp.setContentType(MediaType.APPLICATION_JSON);
                return AuthStatus.SEND_SUCCESS;
            }

            if (req.getRequestURI()
                    .equals(userInfoUri) && isHeadRequest(req)) {
                resp.setContentType(MediaType.APPLICATION_JSON);
                return AuthStatus.SEND_SUCCESS;

            }
            if (!isRetrievalRequest(req)) {
                resp.sendError(HttpURLConnection.HTTP_FORBIDDEN, "Unable to POST when unauthorized.");
                return AuthStatus.SEND_FAILURE;
            }

            return redirectToAuthorizationEndpoint(req, resp, "request is not valid");
        } catch (final AuthException e) {
            // Any problems with the data should be caught and force redirect to
            // authorization endpoint.
            Log.getInstance()
                    .log(Level.FINE, "validationException", e.getMessage());
            Log.getInstance()
                    .throwing(this.getClass()
                            .getName(), "validateRequest", e);
            return AuthStatus.FAILURE;
        } catch (final Exception e) {
            // Any problems with the data should be caught and force redirect to
            // authorization endpoint.
            Log.getInstance()
                    .log(Level.FINE, "validationException", e.getMessage());
            Log.getInstance()
                    .throwing(this.getClass()
                            .getName(), "validateRequest", e);
            return redirectToAuthorizationEndpoint(req, resp, e.getMessage());
        }
    }
}
