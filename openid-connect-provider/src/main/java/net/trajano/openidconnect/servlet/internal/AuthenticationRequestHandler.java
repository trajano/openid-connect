package net.trajano.openidconnect.servlet.internal;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import net.trajano.openidconnect.core.AuthenticationRequestParam;

public class AuthenticationRequestHandler {

    private final Set<String> acrValues;

    private final String clientId;

    private final AuthenticationRequestParam.Display display;

    private final String idTokenHint;

    private final String loginHint;

    private final int maxAge;

    private final String nonce;

    private final Set<AuthenticationRequestParam.Prompt> prompts;

    private final URI redirectUri;

    private final Set<String> responseTypes;

    private final Set<String> scopes;

    private final String state;

    private final List<Locale> uiLocales;

    public AuthenticationRequestHandler(final HttpServletRequest req) throws ServletException {

        scopes = new HashSet<>(Arrays.asList(req.getParameter(AuthenticationRequestParam.SCOPE)
                .split("\\s")));
        if (!scopes.contains("openid")) {
            throw new ServletException("the request must contain the 'openid' scope value");
        }
        responseTypes = new HashSet<>(Arrays.asList(req.getParameter(AuthenticationRequestParam.RESPONSE_TYPE)
                .split("\\s")));
        clientId = req.getParameter(AuthenticationRequestParam.CLIENT_ID);
        redirectUri = URI.create(req.getParameter(AuthenticationRequestParam.REDIRECT_URI));
        state = req.getParameter(AuthenticationRequestParam.STATE);
        nonce = req.getParameter(AuthenticationRequestParam.NONCE);
        display = AuthenticationRequestParam.Display.valueOf(req.getParameter(AuthenticationRequestParam.DISPLAY));
        prompts = new HashSet<>();

        for (final String prompt : req.getParameter(AuthenticationRequestParam.PROMPT)
                .split("\\s")) {
            prompts.add(AuthenticationRequestParam.Prompt.valueOf(prompt));
        }
        if (prompts.contains(AuthenticationRequestParam.Prompt.none) && prompts.size() != 1) {
            throw new ServletException("Cannot have none with any other value for prompt");
        }
        maxAge = Integer.valueOf(req.getParameter(AuthenticationRequestParam.MAX_AGE));
        uiLocales = new ArrayList<>();
        for (final String uiLocale : req.getParameter(AuthenticationRequestParam.UI_LOCALES)
                .split("\\s")) {
            uiLocales.add(new Locale(uiLocale));
        }
        idTokenHint = req.getParameter(AuthenticationRequestParam.ID_TOKEN_HINT);
        loginHint = req.getParameter(AuthenticationRequestParam.LOGIN_HINT);
        acrValues = new HashSet<>(Arrays.asList(req.getParameter(AuthenticationRequestParam.ACR_VALUES)
                .split("\\s")));
    }

}
