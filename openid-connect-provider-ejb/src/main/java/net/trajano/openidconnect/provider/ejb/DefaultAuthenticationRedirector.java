package net.trajano.openidconnect.provider.ejb;

import java.io.IOException;
import java.net.URI;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.core.IdToken;
import net.trajano.openidconnect.core.TokenResponse;
import net.trajano.openidconnect.provider.AuthenticationRedirector;
import net.trajano.openidconnect.provider.AuthenticationRequest;
import net.trajano.openidconnect.provider.ResponseType;
import net.trajano.openidconnect.provider.TokenProvider;

/**
 * Upon successful authentication, implementers are expected to invoke any of
 * the methods below. This class is meant to be injected into a servlet or REST
 * service. ?? should I move this and perhaps key provider into a EJB jar.
 * 
 * @author Archimedes Trajano
 */
@Stateless
public class DefaultAuthenticationRedirector implements AuthenticationRedirector {

    private TokenProvider tokenProvider;

    /**
     * @param responseType
     *            response_type value
     * @param subject
     *            subject
     * @param state
     *            state
     * @param redirectUri
     *            redirect URI.
     * @param extraOptions
     *            extra options for building the idtoken
     */
    private URI buildAuthorizationResponseUri(final AuthenticationRequest request,
            final String subject,
            Object... extraOptions) {

        IdToken idToken = tokenProvider.buildIdToken(subject, extraOptions);
        final String code = tokenProvider.store(idToken, request.getScopes());

        final UriBuilder b = UriBuilder.fromUri(request.getRedirectUri());
        if (request.getState() != null) {
            b.queryParam("state", request.getState());
        }

        if (request.isAuthorizationCodeFlow()) {
            b.queryParam("code", code);
            return b.build();
        }

        boolean implicitFlow = (request.isImplicitFlow());
        TokenResponse tokenResponse = tokenProvider.getByCode(code, implicitFlow);
        if (request.containsResponseType(ResponseType.id_token)) {
            b.queryParam("id_token", tokenResponse.getEncodedIdToken());
        }
        if (request.containsResponseType(ResponseType.token)) {
            b.queryParam("token_type", TokenResponse.BEARER);
            b.queryParam("access_token", tokenResponse.getAccessToken());
        }
        if (request.containsResponseType(ResponseType.code)) {
            b.queryParam("code", code);
        }

        return b.build();
    }

    /**
     * Perform a redirect with the authorization response data.
     * 
     * @param response
     * @param responseType
     * @param subject
     * @param state
     * @param redirectUri
     * @param extraStorageOptions
     * @throws IOException
     */
    @Override
    public void performRedirect(HttpServletResponse response,
            final AuthenticationRequest request,
            final String subject) throws IOException {

        response.sendRedirect(buildAuthorizationResponseUri(request, subject).toASCIIString());
    }

    /**
     * Builds a JAX-RS {@link Response} object containing a redirect
     * 
     * @param responseType
     * @param subject
     * @param state
     * @param redirectUri
     * @param extraStorageOptions
     * @return
     */
    @Override
    public Response buildResponse(final AuthenticationRequest request,
            final String subject) {

        return Response.temporaryRedirect(buildAuthorizationResponseUri(request, subject))
                .build();
    }

    @EJB
    public void setTokenProvider(final TokenProvider tokenProvider) {

        this.tokenProvider = tokenProvider;
    }
}
