package net.trajano.openidconnect.jaspic.internal.processors;

import static net.trajano.openidconnect.core.OpenIdConnectKey.CLIENT_ID;
import static net.trajano.openidconnect.core.OpenIdConnectKey.CLIENT_SECRET;
import static net.trajano.openidconnect.core.OpenIdConnectKey.CODE;
import static net.trajano.openidconnect.core.OpenIdConnectKey.GRANT_TYPE;
import static net.trajano.openidconnect.core.OpenIdConnectKey.REDIRECT_URI;
import static net.trajano.openidconnect.core.OpenIdConnectKey.STATE;
import static net.trajano.openidconnect.jaspic.internal.Utils.isNullOrEmpty;
import static net.trajano.openidconnect.jaspic.internal.Utils.validateIdToken;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.MessageFormat;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.json.JsonObject;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.core.OpenIdProviderConfiguration;
import net.trajano.openidconnect.crypto.Encoding;
import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.crypto.JsonWebTokenProcessor;
import net.trajano.openidconnect.jaspic.OpenIdConnectAuthModule;
import net.trajano.openidconnect.jaspic.internal.CipherUtil;
import net.trajano.openidconnect.jaspic.internal.Log;
import net.trajano.openidconnect.jaspic.internal.TokenCookie;
import net.trajano.openidconnect.jaspic.internal.ValidateContext;
import net.trajano.openidconnect.jaspic.internal.ValidateRequestProcessor;
import net.trajano.openidconnect.token.GrantType;
import net.trajano.openidconnect.token.IdTokenResponse;

public class CallbackRequestProcessor implements
    ValidateRequestProcessor {

    /**
     * https prefix.
     */
    protected static final String HTTPS_PREFIX = "https://";

    private static final Logger LOG = Log.getInstance();

    /**
     * Checks to see whether redirection end point callback the
     * {@link ServerAuthModule} is called by the user agent. This is indicated
     * by the presence of a <code>code</code> and a <code>state</code> on the
     * URL. The user agent would be a web browser that got a redirect or
     * automatic form post sent by the OP.
     */
    @Override
    public boolean canValidateRequest(final ValidateContext context) {

        return context.isSecure() && context.isRequestUri(OpenIdConnectAuthModule.REDIRECTION_ENDPOINT_URI_KEY) && !isNullOrEmpty(context.getReq()
            .getParameter(CODE)) && !isNullOrEmpty(context.getReq()
                .getParameter(STATE));

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
    private IdTokenResponse getToken(final String grantKey,
        final String grant,
        final GrantType grantType,
        final ValidateContext context) throws IOException,
            GeneralSecurityException {

        final MultivaluedMap<String, String> requestData = new MultivaluedHashMap<>();
        requestData.putSingle(grantKey, grant);
        requestData.putSingle(GRANT_TYPE, grantType.name());
        requestData.putSingle(REDIRECT_URI, context.getUri(OpenIdConnectAuthModule.REDIRECTION_ENDPOINT_URI_KEY)
            .toASCIIString());

        try {
            final String authorization = "Basic " + Encoding.base64Encode(context.getOption(OpenIdConnectKey.CLIENT_ID) + ":" + context.getOption(OpenIdConnectKey.CLIENT_SECRET));
            final JsonObject authorizationTokenResponse = context.target(context.getOpenIDProviderConfig()
                .getTokenEndpoint())
                .request(MediaType.APPLICATION_JSON_TYPE)
                .header("Authorization", authorization)
                .post(Entity.form(requestData), JsonObject.class);
            if (LOG.isLoggable(Level.FINEST)) {
                LOG.finest("authorization token response =  " + authorizationTokenResponse);
            }
            return new IdTokenResponse(authorizationTokenResponse);
        } catch (final BadRequestException e) {
            // workaround for google that does not support BASIC authentication
            // on their endpoint.
            requestData.putSingle(CLIENT_ID, context.getOption(OpenIdConnectKey.CLIENT_ID));
            requestData.putSingle(CLIENT_SECRET, context.getOption(OpenIdConnectKey.CLIENT_SECRET));
            final JsonObject authorizationTokenResponse = context.target(context.getOpenIDProviderConfig()
                .getTokenEndpoint())
                .request(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.form(requestData), JsonObject.class);
            if (LOG.isLoggable(Level.FINEST)) {
                LOG.finest("authorization token response =  " + authorizationTokenResponse);
            }
            return new IdTokenResponse(authorizationTokenResponse);
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
    private JsonWebKeySet getWebKeys(final ValidateContext context) throws GeneralSecurityException {

        return context.target(context.getOpenIDProviderConfig()
            .getJwksUri())
            .request(MediaType.APPLICATION_JSON_TYPE)
            .get(JsonWebKeySet.class);
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
        final JsonObject jwtPayload,
        final ValidateContext context) throws GeneralSecurityException {

        try {
            final String iss = googleWorkaround(jwtPayload.getString("iss"));
            context.getHandler()
                .handle(new Callback[] {
                    new CallerPrincipalCallback(subject, UriBuilder.fromUri(iss)
                        .userInfo(jwtPayload.getString("sub"))
                        .build()
                        .toASCIIString()),
                    new GroupPrincipalCallback(subject, new String[] {
                        iss
                            })
            });
        } catch (final IOException
            | UnsupportedCallbackException e) {
            // Should not happen
            LOG.log(Level.SEVERE, "updatePrincipalException", e.getMessage());
            LOG.throwing(this.getClass()
                .getName(), "updateSubjectPrincipal", e);
            throw new AuthException(MessageFormat.format(Log.r("updatePrincipalException"), e.getMessage()));
        }
    }

    @Override
    public AuthStatus validateRequest(final ValidateContext context) throws IOException,
        GeneralSecurityException {

        final OpenIdProviderConfiguration oidProviderConfig = context.getOpenIDProviderConfig();
        final IdTokenResponse token = getToken(OpenIdConnectKey.CODE, context.getReq()
            .getParameter(OpenIdConnectKey.CODE), GrantType.authorization_code, context);
        final net.trajano.openidconnect.crypto.JsonWebKeySet webKeys = getWebKeys(context);

        LOG.log(Level.FINEST, "tokenValue", token);
        final JsonObject claimsSet = new JsonWebTokenProcessor(token.getEncodedIdToken()).jwks(webKeys)
            .getJsonPayload();

        final String nonceCookie = context.getCookie(OpenIdConnectAuthModule.NET_TRAJANO_AUTH_NONCE);
        final String nonce;
        if (nonceCookie != null) {
            nonce = new String(CipherUtil.decrypt(Encoding.base64urlDecode(nonceCookie), context.getSecret()), "US-ASCII");
        } else {
            nonce = null;
        }

        validateIdToken(context.getOption(CLIENT_ID), claimsSet, nonce, token.getAccessToken());

        context.deleteCookie(OpenIdConnectAuthModule.NET_TRAJANO_AUTH_NONCE);

        final String iss = googleWorkaround(claimsSet.getString("iss"));
        final String issuer = googleWorkaround(oidProviderConfig.getIssuer());
        if (!iss.equals(issuer)) {
            LOG.log(Level.SEVERE, "issuerMismatch", new Object[] {
                iss,
                issuer
            });
            throw new GeneralSecurityException(MessageFormat.format(Log.r("issuerMismatch"), iss, issuer));
        }
        updateSubjectPrincipal(context.getClientSubject(), claimsSet, context);

        final TokenCookie tokenCookie;
        if (oidProviderConfig.getUserinfoEndpoint() != null && Pattern.compile("\\bprofile\\b")
            .matcher(context.getOption(OpenIdConnectKey.SCOPE))
            .find()) {
            final Response userInfoResponse = context.target(oidProviderConfig.getUserinfoEndpoint())
                .request(MediaType.APPLICATION_JSON_TYPE)
                .header("Authorization", token.getTokenType() + " " + token.getAccessToken())
                .get();
            if (userInfoResponse.getStatus() == 200) {
                tokenCookie = new TokenCookie(token.getAccessToken(), token.getRefreshToken(), claimsSet, token.getEncodedIdToken(), userInfoResponse.readEntity(JsonObject.class));
            } else {
                LOG.log(Level.WARNING, "unableToGetProfile");
                tokenCookie = new TokenCookie(claimsSet, token.getEncodedIdToken());
            }
        } else {
            tokenCookie = new TokenCookie(claimsSet, token.getEncodedIdToken());
        }

        context.saveIdTokenCookie(tokenCookie);
        context.saveAgeCookie();
        context.redirectToState();
        return AuthStatus.SEND_SUCCESS;
    }
}
