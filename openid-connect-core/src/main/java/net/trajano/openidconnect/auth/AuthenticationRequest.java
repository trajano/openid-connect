package net.trajano.openidconnect.auth;

import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import net.trajano.openidconnect.core.Scope;

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
        if (req.getParameter(AuthenticationRequestParam.DISPLAY) != null && !req.getParameter(AuthenticationRequestParam.DISPLAY)
                .isEmpty()) {
            display = AuthenticationRequestParam.Display.valueOf(req.getParameter(AuthenticationRequestParam.DISPLAY));
        } else {
            display = null;
        }
        prompts = new HashSet<>();

        if (req.getParameter(AuthenticationRequestParam.PROMPT) != null && !req.getParameter(AuthenticationRequestParam.PROMPT)
                .isEmpty()) {
            for (final String prompt : req.getParameter(AuthenticationRequestParam.PROMPT)
                    .split("\\s")) {
                prompts.add(AuthenticationRequestParam.Prompt.valueOf(prompt));
            }
        }

        if (req.getParameter(AuthenticationRequestParam.MAX_AGE) != null && !req.getParameter(AuthenticationRequestParam.MAX_AGE)
                .isEmpty()) {
            maxAge = Integer.valueOf(req.getParameter(AuthenticationRequestParam.MAX_AGE));
        } else {
            maxAge = null;
        }
        uiLocales = new ArrayList<>();
        if (req.getParameter(AuthenticationRequestParam.UI_LOCALES) != null && !req.getParameter(AuthenticationRequestParam.UI_LOCALES)
                .isEmpty()) {
            for (final String uiLocale : req.getParameter(AuthenticationRequestParam.UI_LOCALES)
                    .split("\\s")) {
                uiLocales.add(new Locale(uiLocale));
            }
        }
        idTokenHint = req.getParameter(AuthenticationRequestParam.ID_TOKEN_HINT);
        loginHint = req.getParameter(AuthenticationRequestParam.LOGIN_HINT);
        if (req.getParameter(AuthenticationRequestParam.ACR_VALUES) != null && !req.getParameter(AuthenticationRequestParam.ACR_VALUES)
                .isEmpty()) {
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

    /**
     * Gets a string representation of the scope set.
     * 
     * @return
     */
    public String getScope() {

        StringBuilder b = new StringBuilder();
        Iterator<Scope> i = scopes.iterator();
        b.append(i.next());
        while (i.hasNext()) {
            b.append(' ');
            b.append(i.next());
        }
        return b.toString();
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

    public String getResponseType() {

        StringBuilder b = new StringBuilder();
        Iterator<ResponseType> i = responseTypes.iterator();
        b.append(i.next());
        while (i.hasNext()) {
            b.append(' ');
            b.append(i.next());
        }
        return b.toString();
    }
}
