package net.trajano.openidconnect.auth;

import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.annotation.XmlTransient;

import net.trajano.openidconnect.core.ErrorCode;
import net.trajano.openidconnect.core.RedirectedOpenIdProviderException;
import net.trajano.openidconnect.core.Scope;
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
     *
     */
    private static final long serialVersionUID = 6520962711562750670L;

    private final List<String> acrValues;

    private final String clientId;

    /**
     * Flag to indicate that "code" is the only response type. This is used in a
     * few places so minor efficiency boost.
     */
    @XmlTransient
    private final boolean codeOnlyResponseType;

    private final AuthenticationRequestParam.Display display;

    private final String idTokenHint;

    private final String loginHint;

    private final Integer maxAge;

    private final String nonce;

    private final Set<AuthenticationRequestParam.Prompt> prompts;

    private final URI redirectUri;

    private final ResponseMode responseMode;

    private final Set<ResponseType> responseTypes;

    private final Set<Scope> scopes;

    private final String state;

    private final List<Locale> uiLocales;

    public AuthenticationRequest(final HttpServletRequest req) {

        scopes = Util.getParameterSet(req, AuthenticationRequestParam.SCOPE, Scope.class);
        responseTypes = Util.getParameterSet(req, AuthenticationRequestParam.RESPONSE_TYPE, ResponseType.class);
        codeOnlyResponseType = "code".equals(req.getParameter(AuthenticationRequestParam.RESPONSE_TYPE));

        clientId = req.getParameter(AuthenticationRequestParam.CLIENT_ID);
        redirectUri = URI.create(req.getParameter(AuthenticationRequestParam.REDIRECT_URI));
        state = req.getParameter(AuthenticationRequestParam.STATE);
        nonce = Util.getParameter(req, AuthenticationRequestParam.NONCE);
        display = Util.getParameter(req, AuthenticationRequestParam.DISPLAY, AuthenticationRequestParam.Display.class);
        final ResponseMode responseModeIn = Util.getParameter(req, AuthenticationRequestParam.RESPONSE_MODE, ResponseMode.class);
        if (responseModeIn != null) {
            responseMode = responseModeIn;
        } else {
            responseMode = getDefaultResponseMode();
        }

        prompts = Util.getParameterSet(req, AuthenticationRequestParam.PROMPT, AuthenticationRequestParam.Prompt.class);

        final String maxAgeIn = Util.getParameter(req, AuthenticationRequestParam.MAX_AGE);
        if (maxAgeIn != null) {
            maxAge = Integer.valueOf(maxAgeIn);
        } else {
            maxAge = null;
        }

        uiLocales = new ArrayList<>();
        if (Util.isNotNullOrEmpty(req.getParameter(AuthenticationRequestParam.UI_LOCALES))) {
            for (final String uiLocale : req.getParameter(AuthenticationRequestParam.UI_LOCALES)
                    .split("\\s")) {
                uiLocales.add(new Locale(uiLocale));
            }
        }

        idTokenHint = Util.getParameter(req, AuthenticationRequestParam.ID_TOKEN_HINT);
        loginHint = Util.getParameter(req, AuthenticationRequestParam.LOGIN_HINT);

        acrValues = new ArrayList<>();
        if (Util.isNotNullOrEmpty(req.getParameter(AuthenticationRequestParam.ACR_VALUES))) {
            for (final String acrValue : req.getParameter(AuthenticationRequestParam.ACR_VALUES)
                    .split("\\s+")) {
                acrValues.add(acrValue);
            }
        }

        validate();
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

    public AuthenticationRequestParam.Display getDisplay() {

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

    public Set<AuthenticationRequestParam.Prompt> getPrompts() {

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

    /**
     * Performs the validation on the Authentication token.
     */
    private void validate() {

        if (!scopes.contains(Scope.openid)) {
            throw new RedirectedOpenIdProviderException(this, ErrorCode.invalid_request, "the request must contain the 'openid' scope value");
        }

        if (prompts.contains(AuthenticationRequestParam.Prompt.none) && prompts.size() != 1) {

            throw new RedirectedOpenIdProviderException(this, ErrorCode.invalid_request, "Cannot have 'none' with any other value for 'prompt'");

        }

        if (responseTypes.contains(ResponseType.none) && responseTypes.size() != 1) {

            throw new RedirectedOpenIdProviderException(this, ErrorCode.invalid_request, "Cannot have 'none' with any other value for 'response_type'");

        }

        if (responseMode == ResponseMode.query && !codeOnlyResponseType) {

            throw new RedirectedOpenIdProviderException(this, ErrorCode.invalid_request, "Invalid response mode for the response type requested.");

        }
    }
}
