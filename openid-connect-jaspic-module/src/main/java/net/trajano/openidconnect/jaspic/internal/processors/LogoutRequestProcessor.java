package net.trajano.openidconnect.jaspic.internal.processors;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.core.OpenIdProviderConfiguration;
import net.trajano.openidconnect.crypto.Encoding;
import net.trajano.openidconnect.jaspic.OpenIdConnectAuthModule;
import net.trajano.openidconnect.jaspic.internal.ValidateContext;
import net.trajano.openidconnect.jaspic.internal.ValidateRequestProcessor;

public class LogoutRequestProcessor implements ValidateRequestProcessor {

    /**
     * This only supports the scenario when logout goto uri is not available.
     */
    @Override
    public boolean canValidateRequest(final ValidateContext context) {

        if (context.hasOption(OpenIdConnectAuthModule.LOGOUT_GOTO_URI_KEY)) {
            return false;
        }

        return context.isSecure() && context.isGetRequest() && context.isRequestUri(OpenIdConnectAuthModule.LOGOUT_URI_KEY);
    }

    @Override
    public AuthStatus validateRequest(final ValidateContext context) throws IOException,
            GeneralSecurityException {

        String idTokenHint = context.getTokenCookie()
                .getIdTokenJwt();
        context.deleteAuthCookies();
        final OpenIdProviderConfiguration oidProviderConfig = context.getOpenIDProviderConfig();

        String contextPath = UriBuilder.fromUri(context.getReq()
                .getRequestURL()
                .toString())
                .replacePath(context.getReq()
                        .getContextPath())
                .build()
                .toASCIIString();
        final String referrer = context.getReq()
                .getHeader("Referer");
        if (!referrer.startsWith(contextPath)) {
            throw new AuthException();
        }
        final StringBuilder stateBuilder = new StringBuilder(referrer.substring(contextPath.length()));
        if (context.getReq()
                .getQueryString() != null) {
            stateBuilder.append('?');
            stateBuilder.append(context.getReq()
                    .getQueryString());
        }

        final String state = Encoding.base64UrlEncode(stateBuilder.toString());
        final URI redirectUri = context.getUri("logout_redirection_endpoint");

        if (oidProviderConfig.getEndSessionEndpoint() != null) {
            UriBuilder b = UriBuilder.fromUri(oidProviderConfig.getEndSessionEndpoint())
                    .queryParam("post_logout_redirect_uri", redirectUri)
                    .queryParam("id_token_hint", idTokenHint)
                    .queryParam("state", state);
            context.getResp()
                    .sendRedirect(b.build()
                            .toASCIIString());
        } else {
            context.getResp()
                    .sendRedirect(context.getReq()
                            .getServletContext() + "/");
        }
        return AuthStatus.SEND_SUCCESS;
    }

}
