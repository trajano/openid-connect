package net.trajano.openidconnect.jaspic.internal;

import static net.trajano.openidconnect.jaspic.internal.Utils.isNullOrEmpty;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.json.JsonObject;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;

import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.core.OpenIdProviderConfiguration;
import net.trajano.openidconnect.crypto.Encoding;
import net.trajano.openidconnect.crypto.JsonWebTokenProcessor;
import net.trajano.openidconnect.internal.CharSets;
import net.trajano.openidconnect.jaspic.OpenIdConnectAuthModule;

public class ValidateContext {

    private static final String[] AUTH_COOKIE_NAMES = { OpenIdConnectAuthModule.NET_TRAJANO_AUTH_ID, OpenIdConnectAuthModule.NET_TRAJANO_AUTH_AGE, OpenIdConnectAuthModule.NET_TRAJANO_AUTH_NONCE };

    private final Client client;

    private final Subject clientSubject;

    private final String cookieContext;

    private CallbackHandler handler;

    private final boolean mandatory;

    private OpenIdProviderConfiguration oidConfig;

    private final Map<String, String> options;

    private final HttpServletRequest req;

    private final HttpServletResponse resp;

    private SecretKey secret;

    private final TokenCookie tokenCookie;

    public ValidateContext(final Client client, final Subject clientSubject, final boolean mandatory, final Map<String, String> options, final HttpServletRequest req, final HttpServletResponse resp, final TokenCookie tokenCookie, final String cookieContext, final CallbackHandler handler) {

        this.client = client;
        this.clientSubject = clientSubject;
        this.mandatory = mandatory;
        this.options = options;
        this.req = req;
        this.resp = resp;
        this.tokenCookie = tokenCookie;
        this.handler = handler;

        if (isNullOrEmpty(cookieContext)) {
            this.cookieContext = req.getContextPath();
        } else {
            this.cookieContext = cookieContext;
        }

    }

    /**
     * Deletes the authentication cookies.
     */
    public void deleteAuthCookies() {

        for (final String cookieName : AUTH_COOKIE_NAMES) {
            final Cookie deleteCookie = new Cookie(cookieName, "");
            deleteCookie.setMaxAge(0);
            deleteCookie.setPath(cookieContext);
            resp.addCookie(deleteCookie);
        }

    }

    public void deleteCookie(final String cookieName) {

        final Cookie deleteNonceCookie = new Cookie(cookieName, "");
        deleteNonceCookie.setMaxAge(0);
        deleteNonceCookie.setPath(cookieContext);
        resp.addCookie(deleteNonceCookie);
    }

    public Client getClient() {

        return client;
    }

    public Subject getClientSubject() {

        return clientSubject;
    }

    public String getCookie(final String cookieName) {

        final Cookie[] cookies = req.getCookies();
        if (cookies == null) {
            return null;
        }

        for (final Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    public CallbackHandler getHandler() {

        return handler;
    }

    /**
     * Gets the id_token from the cookie. It will perform the JWT processing
     * needed.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public JsonObject getIdToken() throws IOException,
    GeneralSecurityException {

        return new JsonWebTokenProcessor(tokenCookie.getIdTokenJwt()).signatureCheck(false)
                .getJsonPayload();
    }

    public synchronized OpenIdProviderConfiguration getOpenIDProviderConfig() {

        if (oidConfig == null) {
            final String issuerUri = options.get(OpenIdConnectAuthModule.ISSUER_URI_KEY);
            if (issuerUri == null) {
                // LOG.log(Level.SEVERE, "missingOption", ISSUER_URI_KEY);
                // throw new
                // AuthException(MessageFormat.format(R.getString("missingOption"),
                // ISSUER_URI_KEY));
            }
            oidConfig = client.target(URI.create(issuerUri)
                    .resolve("/.well-known/openid-configuration"))
                    .request(MediaType.APPLICATION_JSON_TYPE)
                    .get(OpenIdProviderConfiguration.class);

        }
        return oidConfig;

    }

    public String getOption(final String key) {

        return options.get(key);
    }

    public Map<String, String> getOptions() {

        return options;
    }

    public HttpServletRequest getReq() {

        return req;
    }

    public HttpServletResponse getResp() {

        return resp;
    }

    public synchronized SecretKey getSecret() throws GeneralSecurityException {

        if (secret == null) {
            secret = CipherUtil.buildSecretKey(options.get(OpenIdConnectKey.CLIENT_ID), options.get(OpenIdConnectKey.CLIENT_SECRET));
        }
        return secret;
    }

    public TokenCookie getTokenCookie() {

        return tokenCookie;
    }

    public URI getUri(final String key) {

        return URI.create(req.getRequestURL()
                .toString())
                .resolve(options.get(key));

    }

    public boolean hasOption(final String key) {

        return options.get(key) != null;
    }

    public boolean hasTokenCookie() {

        return tokenCookie != null;
    }

    /**
     * Checks if the request uses the GET method.
     *
     * @param req
     *            request
     * @return <code>true</code> if the request uses the GET method.
     */
    public boolean isGetRequest() {

        return "GET".equals(req.getMethod());

    }

    public boolean isMandatory() {

        return mandatory;
    }

    /**
     * Checks if the request URI matches the option value for the key provided.
     *
     * @param key
     *            option key
     * @return
     */
    public boolean isRequestUri(final String key) {

        return req.getRequestURI()
                .equals(options.get(key));
    }

    public boolean isSecure() {

        return req.isSecure();
    }

    /**
     * Redirects to the last state. However, if state is equivalent to the
     * logout URI it will redirect to the root.
     *
     * @throws IOException
     */
    public void redirectToState() throws IOException {

        final String stateEncoded = req.getParameter(OpenIdConnectKey.STATE);
        final String contextRedirectUri = Encoding.base64urlDecodeToString(stateEncoded);
        final String targetUri = req.getContextPath() + contextRedirectUri;
        if (targetUri.equals(options.get(OpenIdConnectAuthModule.LOGOUT_URI_KEY))) {
            Log.fine("state was the Logout URI, redirecting to context root");
            resp.sendRedirect(resp.encodeRedirectURL(req.getContextPath()));
        } else {
            resp.sendRedirect(resp.encodeRedirectURL(targetUri));
        }

    }

    public void saveAgeCookie() throws GeneralSecurityException,
    IOException {

        final Cookie ageCookie = new Cookie(OpenIdConnectAuthModule.NET_TRAJANO_AUTH_AGE, Encoding.base64urlEncode(CipherUtil.encrypt(req.getRemoteAddr()
                .getBytes(CharSets.US_ASCII), secret)));
        if (isNullOrEmpty(req.getParameter("expires_in"))) {
            ageCookie.setMaxAge(3600);

        } else {
            ageCookie.setMaxAge(Integer.parseInt(req.getParameter("expires_in")));
        }
        ageCookie.setPath(cookieContext);
        ageCookie.setSecure(true);
        ageCookie.setHttpOnly(true);
        resp.addCookie(ageCookie);

    }

    /**
     * Saves the ID Token cookie.
     *
     * @param tokenCookie
     * @throws GeneralSecurityException
     */
    public void saveIdTokenCookie(final TokenCookie tokenCookie) throws GeneralSecurityException {

        final Cookie idTokenCookie = new Cookie(OpenIdConnectAuthModule.NET_TRAJANO_AUTH_ID, tokenCookie.toCookieValue(getSecret()));
        idTokenCookie.setMaxAge(-1);
        idTokenCookie.setSecure(true);
        idTokenCookie.setHttpOnly(true);
        idTokenCookie.setPath(cookieContext);
        resp.addCookie(idTokenCookie);
    }

    public void setContentType(final String contentType) {

        resp.setContentType(contentType);

    }

    public WebTarget target(final URI uri) {

        return client.target(uri);
    }
}
