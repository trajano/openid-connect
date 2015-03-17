package net.trajano.openidconnect.jaspic.internal;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Map;

import javax.json.JsonObject;
import javax.security.auth.Subject;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.Client;
import javax.ws.rs.core.MediaType;

import net.trajano.openidconnect.core.OpenIdProviderConfiguration;
import net.trajano.openidconnect.crypto.JsonWebTokenProcessor;
import net.trajano.openidconnect.jaspic.OpenIdConnectAuthModule;

public class ValidateContext {

    private final Client client;

    private final Subject clientSubject;

    private final boolean mandatory;

    private final Map<String, String> options;

    private final HttpServletRequest req;

    private final HttpServletResponse resp;

    private final TokenCookie tokenCookie;

    private final String cookieContext;

    public ValidateContext(final Client client, final Subject clientSubject, final boolean mandatory, final Map<String, String> options, final HttpServletRequest req, final HttpServletResponse resp, final TokenCookie tokenCookie, String cookieContext) {

        this.client = client;
        this.clientSubject = clientSubject;
        this.mandatory = mandatory;
        this.options = options;
        this.req = req;
        this.resp = resp;
        this.tokenCookie = tokenCookie;
        this.cookieContext = cookieContext;
    }

    public Client getClient() {

        return client;
    }

    public Subject getClientSubject() {

        return clientSubject;
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

    public Map<String, String> getOptions() {

        return options;
    }

    public HttpServletRequest getReq() {

        return req;
    }

    public HttpServletResponse getResp() {

        return resp;
    }

    public TokenCookie getTokenCookie() {

        return tokenCookie;
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

    public void setContentType(final String contentType) {

        resp.setContentType(contentType);

    }

    private static final String[] AUTH_COOKIE_NAMES = { OpenIdConnectAuthModule.NET_TRAJANO_AUTH_ID, OpenIdConnectAuthModule.NET_TRAJANO_AUTH_AGE, OpenIdConnectAuthModule.NET_TRAJANO_AUTH_NONCE };

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

    public OpenIdProviderConfiguration getOpenIDProviderConfig() {

        final String issuerUri = options.get(OpenIdConnectAuthModule.ISSUER_URI_KEY);
        if (issuerUri == null) {
            // LOG.log(Level.SEVERE, "missingOption", ISSUER_URI_KEY);
            // throw new
            // AuthException(MessageFormat.format(R.getString("missingOption"),
            // ISSUER_URI_KEY));
        }
        return client.target(URI.create(issuerUri)
                .resolve("/.well-known/openid-configuration"))
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(OpenIdProviderConfiguration.class);

    }

    public URI getUri(String key) {

        return URI.create(req.getRequestURL()
                .toString())
                .resolve(options.get(key));

    }

    public boolean hasOption(String key) {

        return options.get(key) != null;
    }

    public String getOption(String key) {

        return options.get(key);
    }
}
