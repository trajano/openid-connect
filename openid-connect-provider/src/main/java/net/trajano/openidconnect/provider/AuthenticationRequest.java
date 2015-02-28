package net.trajano.openidconnect.provider;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import net.trajano.openidconnect.core.AuthenticationRequestParam;
import net.trajano.openidconnect.core.ResponseType;
import net.trajano.openidconnect.core.Scope;

/**
 * Wraps an HttpServletRequest to provide a cleaner API to the request
 * parameters.
 * 
 * @author Archimedes
 */
public class AuthenticationRequest {

    private final Set<String> acrValues;

    private final String clientId;

    private final AuthenticationRequestParam.Display display;

    private final String idTokenHint;

    private final String loginHint;

    private final Integer maxAge;

    private final String nonce;

    private final Set<AuthenticationRequestParam.Prompt> prompts;

    private final URI redirectUri;

    private final Set<ResponseType> responseTypes;

    private final Set<Scope> scopes;

    private final String state;

    private final List<Locale> uiLocales;

    public AuthenticationRequest(final HttpServletRequest req) {

        scopes = new HashSet<>();
        for (final String scope : req.getParameter(AuthenticationRequestParam.SCOPE)
                .split("\\s")) {
            scopes.add(Scope.valueOf(scope));
        }
        responseTypes = new HashSet<>();
        for (final String responseType : req.getParameter(AuthenticationRequestParam.RESPONSE_TYPE)
                .split("\\s")) {
            responseTypes.add(ResponseType.valueOf(responseType));
        }

        clientId = req.getParameter(AuthenticationRequestParam.CLIENT_ID);
        redirectUri = URI.create(req.getParameter(AuthenticationRequestParam.REDIRECT_URI));
        state = req.getParameter(AuthenticationRequestParam.STATE);
        nonce = req.getParameter(AuthenticationRequestParam.NONCE);
        if (req.getParameter(AuthenticationRequestParam.DISPLAY) != null) {
            display = AuthenticationRequestParam.Display.valueOf(req.getParameter(AuthenticationRequestParam.DISPLAY));
        } else {
            display = null;
        }
        prompts = new HashSet<>();

        if (req.getParameter(AuthenticationRequestParam.PROMPT) != null) {
            for (final String prompt : req.getParameter(AuthenticationRequestParam.PROMPT)
                    .split("\\s")) {
                prompts.add(AuthenticationRequestParam.Prompt.valueOf(prompt));
            }
        }

        if (req.getParameter(AuthenticationRequestParam.MAX_AGE) != null) {
            maxAge = Integer.valueOf(req.getParameter(AuthenticationRequestParam.MAX_AGE));
        } else {
            maxAge = null;
        }
        uiLocales = new ArrayList<>();
        if (req.getParameter(AuthenticationRequestParam.UI_LOCALES) != null) {
            for (final String uiLocale : req.getParameter(AuthenticationRequestParam.UI_LOCALES)
                    .split("\\s")) {
                uiLocales.add(new Locale(uiLocale));
            }
        }
        idTokenHint = req.getParameter(AuthenticationRequestParam.ID_TOKEN_HINT);
        loginHint = req.getParameter(AuthenticationRequestParam.LOGIN_HINT);
        if (req.getParameter(AuthenticationRequestParam.ACR_VALUES) != null) {
            acrValues = new HashSet<>(Arrays.asList(req.getParameter(AuthenticationRequestParam.ACR_VALUES)
                    .split("\\s")));
        } else {
            acrValues = Collections.emptySet();
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
     * If the response types contains code and only code.
     * 
     * @return
     */
    public boolean isAuthorizationCodeFlow() {

        return responseTypes.equals(Collections.singleton(ResponseType.code));
    }

    public Set<String> getAcrValues() {

        return acrValues;
    }

    public String getClientId() {

        return clientId;
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

    public Set<ResponseType> getResponseTypes() {

        return responseTypes;
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

    public boolean containsResponseType(ResponseType responseType) {

        return responseTypes.contains(responseType);
    }
}
