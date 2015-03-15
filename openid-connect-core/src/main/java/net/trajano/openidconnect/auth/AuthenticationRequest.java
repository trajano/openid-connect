package net.trajano.openidconnect.auth;

import static net.trajano.openidconnect.core.ErrorCode.invalid_request;

import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue.ValueType;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.core.UriBuilder;
import javax.xml.bind.annotation.XmlTransient;

import net.trajano.openidconnect.core.ErrorResponse;
import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.core.RedirectedOpenIdProviderException;
import net.trajano.openidconnect.core.Scope;
import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.crypto.JsonWebToken;
import net.trajano.openidconnect.crypto.JsonWebTokenProcessor;
import net.trajano.openidconnect.internal.Util;

/**
 * Wraps an HttpServletRequest to provide a cleaner API to the request
 * parameters. This is {@link Serializable} in order to allow implementations to
 * use Object Input/Output streams to build the data as needed.
 *
 * @author Archimedes
 */
public class AuthenticationRequest implements Serializable {

    /**
     * Builder for the Authentication request
     *
     * @author Archimedes
     */
    public static class Builder {

        private final Map<String, String> requestMap = new HashMap<>();

        public AuthenticationRequest build() throws IOException,
                GeneralSecurityException {

            return new AuthenticationRequest(requestMap);
        }

        public Builder clientId(final String s) {

            requestMap.put(OpenIdConnectKey.CLIENT_ID, s);
            return this;
        }

        public Builder nonce(final String s) {

            requestMap.put(OpenIdConnectKey.NONCE, s);
            return this;
        }

        public Builder redirectUri(final URI uri) {

            requestMap.put(OpenIdConnectKey.REDIRECT_URI, uri.toASCIIString());
            return this;
        }

        public Builder responseMode(final ResponseMode mode) {

            if (mode != ResponseMode.query) {
                requestMap.put(OpenIdConnectKey.RESPONSE_MODE, mode.name());
            }
            return this;
        }

        public Builder responseType(@NotNull final ResponseType code,
                final ResponseType... oth) {

            final StringBuilder b = new StringBuilder(code.name());
            for (final ResponseType type : oth) {
                b.append(' ');
                b.append(type.name());
            }
            requestMap.put(OpenIdConnectKey.RESPONSE_TYPE, b.toString());
            return this;
        }

        public Builder scope(final String scope) {

            requestMap.put(OpenIdConnectKey.SCOPE, scope);
            return this;
        }

        public Builder state(final String s) {

            requestMap.put(OpenIdConnectKey.STATE, s);
            return this;
        }

        public Builder uiLocale(final Enumeration<Locale> locales) {

            if (locales != null) {
                final StringBuilder b = new StringBuilder(locales.nextElement()
                        .toLanguageTag());

                while (locales.hasMoreElements()) {
                    b.append(' ');
                    b.append(locales.nextElement()
                            .toLanguageTag());
                }
                requestMap.put(OpenIdConnectKey.UI_LOCALES, b.toString());
            }
            return this;
        }
    }

    private static final String[] REQUEST_KEYS = { OpenIdConnectKey.ACR_VALUES, OpenIdConnectKey.CLIENT_ID, OpenIdConnectKey.DISPLAY, OpenIdConnectKey.ID_TOKEN_HINT, OpenIdConnectKey.LOGIN_HINT, OpenIdConnectKey.MAX_AGE, OpenIdConnectKey.NONCE, OpenIdConnectKey.PROMPT, OpenIdConnectKey.REDIRECT_URI, OpenIdConnectKey.RESPONSE_MODE, OpenIdConnectKey.RESPONSE_TYPE, OpenIdConnectKey.SCOPE, OpenIdConnectKey.STATE, OpenIdConnectKey.UI_LOCALES };

    /**
     *
     */
    private static final long serialVersionUID = 6520962711562750670L;

    private static Map<String, String> buildRequestMap(final HttpServletRequest req,
            final JsonWebKeySet privateJwks) throws IOException,
            GeneralSecurityException {

        final Map<String, String> requestMap = new HashMap<>();

        final JsonObject requestObject;
        if (req.getParameter(OpenIdConnectKey.REQUEST) != null && privateJwks != null) {
            final JsonWebToken jwt = new JsonWebToken(req.getParameter(OpenIdConnectKey.REQUEST));
            final JsonWebTokenProcessor p = new JsonWebTokenProcessor(jwt).jwks(privateJwks);
            requestObject = p.getJsonPayload();
        } else {
            requestObject = null;
        }
        for (final String key : REQUEST_KEYS) {
            processValueFromMapOrObject(requestMap, key, req, requestObject);
        }
        return requestMap;
    }

    private static Map<String, String> buildRequestMap(final String requestJwt,
            final JsonWebKeySet privateJwks) throws IOException,
            GeneralSecurityException {

        final Map<String, String> requestMap = new HashMap<>();

        final JsonObject requestObject;
        if (requestJwt != null && privateJwks != null) {
            final JsonWebToken jwt = new JsonWebToken(requestJwt);
            final JsonWebTokenProcessor p = new JsonWebTokenProcessor(jwt).jwks(privateJwks);
            requestObject = p.getJsonPayload();
        } else {
            requestObject = null;
        }
        for (final String key : REQUEST_KEYS) {
            processValueFromMapOrObject(requestMap, key, null, requestObject);
        }
        return requestMap;
    }

    /**
     * <p>
     * So that the request is a valid OAuth 2.0 Authorization Request, values
     * for the response_type and client_id parameters MUST be included using the
     * OAuth 2.0 request syntax, since they are REQUIRED by OAuth 2.0. The
     * values for these parameters MUST match those in the Request Object, if
     * present.
     * </p>
     *
     * @param reqMap
     * @param key
     * @param servletRequest
     * @param requestObject
     */
    private static void processValueFromMapOrObject(final Map<String, String> reqMap,
            final String key,
            final HttpServletRequest servletRequest,
            final JsonObject requestObject) {

        final String paramValue;
        if (servletRequest != null && servletRequest.getParameter(key) != null) {
            paramValue = servletRequest.getParameter(key);
        } else {
            paramValue = null;
        }

        final String requestObjectValue;
        if (requestObject == null || !requestObject.containsKey(key)) {
            requestObjectValue = null;
        } else if (requestObject.get(key)
                .getValueType() == ValueType.STRING) {
            requestObjectValue = requestObject.getString(key);
        } else if (requestObject.get(key)
                .getValueType() == ValueType.NUMBER) {
            requestObjectValue = requestObject.getJsonNumber(key)
                    .bigIntegerValueExact()
                    .toString();
        } else {
            requestObjectValue = null;
        }

        if (OpenIdConnectKey.CLIENT_ID.equals(key) && paramValue != null & requestObjectValue != null && !paramValue.equals(requestObjectValue)) {
            throw new BadRequestException("client_id does not match.");
        }

        if (OpenIdConnectKey.REDIRECT_URI.equals(key) && paramValue != null & requestObjectValue != null && !paramValue.equals(requestObjectValue)) {
            throw new BadRequestException("redirect_uri does not match.");
        }

        if (Util.isNotNullOrEmpty(requestObjectValue)) {
            reqMap.put(key, requestObjectValue);
        } else if (Util.isNotNullOrEmpty(paramValue)) {
            reqMap.put(key, paramValue);
        }
    }

    private final List<String> acrValues;

    private final String clientId;

    /**
     * Flag to indicate that "code" is the only response type. This is used in a
     * few places so minor efficiency boost.
     */
    @XmlTransient
    private final boolean codeOnlyResponseType;

    private final Display display;

    private final String idTokenHint;

    private final String loginHint;

    private final Integer maxAge;

    private final String nonce;

    private final Set<Prompt> prompts;

    private final URI redirectUri;

    /**
     * Stringified values for the request.
     */
    private final Map<String, String> requestMap;

    private final ResponseMode responseMode;

    private final Set<ResponseType> responseTypes;

    private final Set<Scope> scopes;

    private final String state;

    private final List<Locale> uiLocales;

    public AuthenticationRequest(final HttpServletRequest req, final JsonWebKeySet privateJwks) throws IOException, GeneralSecurityException {

        this(buildRequestMap(req, privateJwks));
    }

    private AuthenticationRequest(final Map<String, String> requestMap) throws IOException, GeneralSecurityException {

        this.requestMap = requestMap;
        if (requestMap.containsKey(OpenIdConnectKey.ACR_VALUES)) {
            acrValues = Util.splitToList(requestMap.get(OpenIdConnectKey.ACR_VALUES));
        } else {
            acrValues = null;
        }
        if (requestMap.containsKey(OpenIdConnectKey.CLIENT_ID)) {
            clientId = requestMap.get(OpenIdConnectKey.CLIENT_ID);
        } else {
            clientId = null;
        }
        if (requestMap.containsKey(OpenIdConnectKey.DISPLAY)) {
            display = Util.valueOf(Display.class, requestMap.get(OpenIdConnectKey.DISPLAY));
        } else {
            display = null;
        }

        if (requestMap.containsKey(OpenIdConnectKey.ID_TOKEN_HINT)) {
            idTokenHint = requestMap.get(OpenIdConnectKey.ID_TOKEN_HINT);
        } else {
            idTokenHint = null;
        }

        if (requestMap.containsKey(OpenIdConnectKey.LOGIN_HINT)) {
            loginHint = requestMap.get(OpenIdConnectKey.LOGIN_HINT);
        } else {
            loginHint = null;
        }

        if (requestMap.containsKey(OpenIdConnectKey.MAX_AGE)) {
            maxAge = Integer.valueOf(requestMap.get(OpenIdConnectKey.MAX_AGE));
        } else {
            maxAge = null;
        }

        if (requestMap.containsKey(OpenIdConnectKey.NONCE)) {
            nonce = requestMap.get(OpenIdConnectKey.NONCE);
        } else {
            nonce = null;
        }

        if (requestMap.containsKey(OpenIdConnectKey.PROMPT)) {
            prompts = Util.splitToSet(Prompt.class, requestMap.get(OpenIdConnectKey.PROMPT));
        } else {
            prompts = Collections.emptySet();
        }

        if (requestMap.containsKey(OpenIdConnectKey.REDIRECT_URI)) {
            redirectUri = URI.create(requestMap.get(OpenIdConnectKey.REDIRECT_URI));
        } else {
            redirectUri = null;
        }

        if (requestMap.containsKey(OpenIdConnectKey.RESPONSE_TYPE)) {
            responseTypes = Util.splitToSet(ResponseType.class, requestMap.get(OpenIdConnectKey.RESPONSE_TYPE));
        } else {
            responseTypes = Collections.emptySet();
        }
        codeOnlyResponseType = responseTypes.equals(Collections.singleton(ResponseType.code));

        if (requestMap.containsKey(OpenIdConnectKey.RESPONSE_MODE)) {
            responseMode = Util.valueOf(ResponseMode.class, requestMap.get(OpenIdConnectKey.RESPONSE_MODE));
        } else {
            responseMode = getDefaultResponseMode();
        }

        if (requestMap.containsKey(OpenIdConnectKey.SCOPE)) {
            scopes = Util.splitToSet(Scope.class, requestMap.get(OpenIdConnectKey.SCOPE));
        } else {
            scopes = null;
        }

        if (requestMap.containsKey(OpenIdConnectKey.STATE)) {
            state = requestMap.get(OpenIdConnectKey.STATE);
        } else {
            state = null;
        }

        if (requestMap.containsKey(OpenIdConnectKey.UI_LOCALES)) {
            uiLocales = Util.splitToLocaleList(requestMap.get(OpenIdConnectKey.UI_LOCALES));
        } else {
            uiLocales = null;
        }

        validate();
    }

    /**
     * Constructs the authentication request using the Request JWT.
     *
     * @param requestJwt
     *            request JWT
     * @param privateJwks
     *            JWKS containing private keys if necessary.
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public AuthenticationRequest(final String requestJwt, final JsonWebKeySet privateJwks) throws IOException, GeneralSecurityException {

        this(buildRequestMap(requestJwt, privateJwks));
    }

    public void addQueryParams(final UriBuilder b) {

        for (final Entry<String, String> entry : requestMap.entrySet()) {
            b.queryParam(entry.getKey(), entry.getValue());
        }
    }

    public boolean containsResponseType(final ResponseType responseType) {

        return responseTypes.contains(responseType);
    }

    public List<String> getAcrValues() {

        return acrValues;
    }

    public String getClientId() {

        return clientId;
    }

    /**
     * For purposes of this specification, the default Response Mode for the
     * OAuth 2.0 code Response Type is the query encoding. For purposes of this
     * specification, the default Response Mode for the OAuth 2.0 token Response
     * Type is the fragment encoding.
     *
     * @return
     */
    private ResponseMode getDefaultResponseMode() {

        if (codeOnlyResponseType) {
            return ResponseMode.query;
        } else {
            return ResponseMode.fragment;
        }

    }

    public Display getDisplay() {

        return display;
    }

    public String getIdTokenHint() {

        return idTokenHint;
    }

    public String getLoginHint() {

        return loginHint;
    }

    public Integer getMaxAge() {

        return maxAge;
    }

    public String getNonce() {

        return nonce;
    }

    public Set<Prompt> getPrompts() {

        return prompts;
    }

    public URI getRedirectUri() {

        return redirectUri;
    }

    public ResponseMode getResponseMode() {

        return responseMode;
    }

    public String getResponseType() {

        final StringBuilder b = new StringBuilder();
        final Iterator<ResponseType> i = responseTypes.iterator();
        b.append(i.next());
        while (i.hasNext()) {
            b.append(' ');
            b.append(i.next());
        }
        return b.toString();
    }

    public Set<ResponseType> getResponseTypes() {

        return responseTypes;
    }

    /**
     * Gets a string representation of the scope set.
     *
     * @return
     */
    public String getScope() {

        final StringBuilder b = new StringBuilder();
        final Iterator<Scope> i = scopes.iterator();
        b.append(i.next());
        while (i.hasNext()) {
            b.append(' ');
            b.append(i.next());
        }
        return b.toString();
    }

    public Set<Scope> getScopes() {

        return scopes;
    }

    public String getState() {

        return state;
    }

    public List<Locale> getUiLocales() {

        return uiLocales;
    }

    /**
     * If the response types contains code and only code.
     *
     * @return
     */
    public boolean isAuthorizationCodeFlow() {

        return codeOnlyResponseType;
    }

    public boolean isDefaultResponseMode() {

        if (codeOnlyResponseType) {
            return ResponseMode.query == responseMode;
        } else {
            return ResponseMode.fragment == responseMode;
        }
    }

    /**
     * All but the code Response Type value, which is defined by OAuth 2.0
     * [RFC6749], are defined in the OAuth 2.0 Multiple Response Type Encoding
     * Practices [OAuth.Responses] specification. NOTE: While OAuth 2.0 also
     * defines the token Response Type value for the Implicit Flow, OpenID
     * Connect does not use this Response Type, since no ID Token would be
     * returned.
     *
     * @see http://openid.net/specs/openid-connect-core-1_0.html#Authentication
     * @return
     */
    public boolean isImplicitFlow() {

        return !responseTypes.contains(ResponseType.code);
    }

    public JsonObject toJsonObject() {

        final JsonObjectBuilder b = Json.createObjectBuilder();
        b.add(OpenIdConnectKey.CLIENT_ID, clientId);
        b.add(OpenIdConnectKey.REDIRECT_URI, redirectUri.toASCIIString());
        if (display != null) {
            b.add(OpenIdConnectKey.DISPLAY, Util.toString(display));
        }
        if (idTokenHint != null) {
            b.add(OpenIdConnectKey.ID_TOKEN_HINT, idTokenHint);
        }
        if (loginHint != null) {
            b.add(OpenIdConnectKey.LOGIN_HINT, loginHint);
        }
        if (maxAge != null) {
            b.add(OpenIdConnectKey.MAX_AGE, maxAge);
        }
        if (nonce != null) {
            b.add(OpenIdConnectKey.NONCE, nonce);
        }
        if (responseMode != null) {
            b.add(OpenIdConnectKey.RESPONSE_MODE, Util.toString(responseMode));
        }
        if (responseTypes != null) {
            b.add(OpenIdConnectKey.RESPONSE_TYPE, Util.toString(responseTypes));
        }
        if (scopes != null) {
            b.add(OpenIdConnectKey.SCOPE, Util.toString(scopes));
        }
        if (state != null) {
            b.add(OpenIdConnectKey.STATE, state);
        }
        if (acrValues != null) {
            b.add(OpenIdConnectKey.ACR_VALUES, Util.join(acrValues));
        }
        if (uiLocales != null) {
            b.add(OpenIdConnectKey.UI_LOCALES, Util.toLocaleString(uiLocales));
        }
        return b.build();
    }

    /**
     * Performs the validation on the Authentication token.
     */
    private void validate() {

        if (redirectUri == null) {
            throw new BadRequestException("the request must contain the 'redirect_uri'");
        }

        if (clientId == null) {
            throw new RedirectedOpenIdProviderException(this, new ErrorResponse(invalid_request, "the request must contain the 'client_id'"));
        }

        if (!scopes.contains(Scope.openid)) {
            throw new RedirectedOpenIdProviderException(this, new ErrorResponse(invalid_request, "the request must contain the 'openid' scope value"));
        }

        if (prompts.contains(Prompt.none) && prompts.size() != 1) {

            throw new RedirectedOpenIdProviderException(this, new ErrorResponse(invalid_request, "Cannot have 'none' with any other value for 'prompt'"));

        }

        if (responseTypes.contains(ResponseType.none) && responseTypes.size() != 1) {

            throw new RedirectedOpenIdProviderException(this, new ErrorResponse(invalid_request, "Cannot have 'none' with any other value for 'response_type'"));

        }

        if (responseMode == ResponseMode.query && !codeOnlyResponseType) {

            throw new RedirectedOpenIdProviderException(this, new ErrorResponse(invalid_request, "Invalid response mode for the response type requested."));

        }
    }
}
